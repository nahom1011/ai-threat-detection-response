"""
API module for the dashboard.

Provides REST API endpoints for retrieving statistics, alerts, history,
and performing administrative actions like unblocking IPs.
"""

import sqlite3
import logging
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import ipaddress

# Add src to path for importing backend modules
src_path = Path(__file__).parent.parent / 'src'
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from response import ResponseManager
from config import load_config as load_backend_config

from dashboard.config import DashboardConfig


logger = logging.getLogger(__name__)


class DashboardAPI:
    """
    API layer for dashboard data retrieval and actions.
    
    Interfaces with the existing backend database and response manager.
    """
    
    def __init__(self, threat_db_path: Optional[str] = None):
        """
        Initialize the dashboard API.
        
        Args:
            threat_db_path: Path to threat detection database
        """
        self.db_path = Path(threat_db_path or DashboardConfig.THREAT_DB_PATH)
        
        if not self.db_path.exists():
            logger.warning(f"Threat database does not exist yet: {self.db_path}")
        
        logger.info(f"DashboardAPI initialized with database: {self.db_path}")
    
    def _get_db_connection(self) -> sqlite3.Connection:
        """
        Get a database connection.
        
        Returns:
            SQLite connection object
            
        Raises:
            RuntimeError: If database connection fails
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable dict-like access
            return conn
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise RuntimeError(f"Failed to connect to database: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get dashboard statistics.
        
        Returns:
            Dictionary containing:
            - packets_analyzed: Total flows processed (from flow_scores count)
            - active_threats: Count of high-confidence detections (score >= 0.85)
            - traffic_volume: Total bytes processed (derived from flow count)
            - blocked_ips: Count of currently blocked IPs (from active_blocks)
            
        Note: Some metrics are estimates based on available data.
        """
        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            
            # Total flows analyzed
            cursor.execute("SELECT COUNT(*) FROM flow_scores")
            packets_analyzed = cursor.fetchone()[0]
            
            # Active threats (flows with score >= 0.85)
            # Need to handle score conversion for comparison
            cursor.execute("SELECT score FROM flow_scores ORDER BY timestamp DESC LIMIT 1000")
            
            scores = []
            try:
                scores = cursor.fetchall()
            except Exception as db_err:
                logger.warning(f"Stopped fetching scores due to error (DB may be malformed): {db_err}")
                
            active_threats = 0
            for row in scores:
                score_raw = row['score'] if hasattr(row, 'keys') else row[0]
                try:
                    if isinstance(score_raw, bytes):
                        import struct
                        if len(score_raw) == 4:
                            score = struct.unpack('f', score_raw)[0]
                        elif len(score_raw) == 8:
                            score = struct.unpack('d', score_raw)[0]
                        else:
                            score = 0.0
                    elif isinstance(score_raw, str):
                        score = float(score_raw)
                    else:
                        score = float(score_raw) if score_raw is not None else 0.0
                    
                    if score >= DashboardConfig.CONFIDENCE_THRESHOLD:
                        active_threats += 1
                except:
                    pass
            
            # Traffic volume estimate (each flow represents some traffic)
            # This is a simplified metric - actual byte count would require Suricata data
            traffic_volume = packets_analyzed * 1500  # Approximate avg packet size
            
            # Currently blocked IPs
            cursor.execute("SELECT COUNT(*) FROM active_blocks")
            blocked_ips = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'packets_analyzed': packets_analyzed,
                'active_threats': active_threats,
                'traffic_volume': traffic_volume,
                'blocked_ips': blocked_ips
            }
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {
                'packets_analyzed': 0,
                'active_threats': 0,
                'traffic_volume': 0,
                'blocked_ips': 0
            }
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recent threat alerts (high-scoring flows).
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of alert dictionaries, newest first
        """
        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            
            # Get ALL flows, not just high-scoring ones
            cursor.execute("""
                SELECT 
                    timestamp,
                    src_ip,
                    dest_ip,
                    dest_port,
                    proto,
                    score,
                    prediction,
                    action_taken
                FROM flow_scores
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            alerts = []
            for row in rows:
                # Determine status based on action_taken and score
                action = row['action_taken'] or 'NONE'
                
                # Convert score to float (handle bytes/blob from SQLite)
                score_raw = row['score']
                if isinstance(score_raw, bytes):
                    # If stored as bytes/blob, convert from 4-byte float
                    import struct
                    if len(score_raw) == 4:
                        score = struct.unpack('f', score_raw)[0]
                    elif len(score_raw) == 8:
                        score = struct.unpack('d', score_raw)[0]
                    else:
                        score = 0.0
                elif isinstance(score_raw, str):
                    score = float(score_raw)
                else:
                    score = float(score_raw) if score_raw is not None else 0.0
                
                if 'BLOCKED' in action:
                    status = 'Blocked'
                elif score >= DashboardConfig.CONFIDENCE_THRESHOLD:
                    status = 'Critical'
                elif score >= 0.50:
                    status = 'Logged'
                else:
                    status = 'Low'
                
                # Derive attack type from action and prediction
                attack_type = self._derive_attack_type(
                    row['prediction'],
                    action,
                    score
                )
                
                alerts.append({
                    'timestamp': row['timestamp'],
                    'source_ip': row['src_ip'],
                    'destination_ip': row['dest_ip'],
                    'destination_port': row['dest_port'] or 0,
                    'protocol': row['proto'] or 'Unknown',
                    'score': float(score),
                    'status': status,
                    'attack_type': attack_type,
                    'action': action
                })
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error getting recent alerts: {e}")
            return []
    
    def get_audit_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit log history.
        
        Args:
            limit: Maximum number of records to return
            
        Returns:
            List of audit log dictionaries, newest first
        """
        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    timestamp,
                    action,
                    ip,
                    actor,
                    reason,
                    score,
                    details
                FROM audit_log
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            history = []
            for row in rows:
                score_raw = row['score']
                if isinstance(score_raw, bytes):
                    import struct
                    if len(score_raw) == 4:
                        score = struct.unpack('f', score_raw)[0]
                    elif len(score_raw) == 8:
                        score = struct.unpack('d', score_raw)[0]
                    else:
                        score = 0.0
                elif isinstance(score_raw, str):
                    score = float(score_raw)
                else:
                    score = float(score_raw) if score_raw is not None else None

                history.append({
                    'timestamp': row['timestamp'],
                    'action': row['action'],
                    'ip': row['ip'],
                    'actor': row['actor'],
                    'reason': row['reason'] or 'N/A',
                    'score': score
                })
            
            return history
            
        except Exception as e:
            logger.error(f"Error getting audit history: {e}")
            return []
    
    def unblock_ip_address(self, ip: str, actor: str) -> Dict[str, Any]:
        """
        Unblock an IP address using the existing backend response manager.
        
        Args:
            ip: IP address to unblock
            actor: Username of person initiating unblock
            
        Returns:
            Dictionary with success status and message
        """
        # Validate IP address
        if not self._is_valid_ip(ip):
            logger.warning(f"Invalid IP address format: {ip}")
            return {
                'success': False,
                'message': 'Invalid IP address format'
            }
        
        try:
            # Load backend configuration
            backend_config = load_backend_config('config.yaml')
            
            # Create ResponseManager instance
            response_manager = ResponseManager(
                db_path=backend_config.database.path,
                whitelist=backend_config.response.whitelist,
                firewall_rule_prefix=backend_config.response.firewall_rule_prefix,
                cleanup_interval=backend_config.response.cleanup_interval
            )
            
            # Check if IP is actually blocked
            if not response_manager.is_blocked(ip):
                logger.info(f"IP {ip} is not currently blocked")
                return {
                    'success': False,
                    'message': f'IP {ip} is not currently blocked'
                }
            
            # Perform unblock using existing backend function
            success = response_manager.unblock_ip(ip, actor=actor)
            
            if success:
                logger.info(f"Successfully unblocked {ip} by {actor}")
                return {
                    'success': True,
                    'message': f'IP {ip} unblocked successfully'
                }
            else:
                logger.error(f"Failed to unblock {ip}")
                return {
                    'success': False,
                    'message': 'Unblock operation failed'
                }
            
        except Exception as e:
            logger.error(f"Error unblocking IP {ip}: {e}", exc_info=True)
            return {
                'success': False,
                'message': 'Internal server error'
            }
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """
        Validate IP address format.
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid IPv4 or IPv6 address
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def _derive_attack_type(
        prediction: Optional[str],
        action: Optional[str],
        score: float
    ) -> str:
        """
        Derive attack type description from available data.
        
        Args:
            prediction: Model prediction ('MALICIOUS', 'BENIGN', etc.)
            action: Action taken ('BLOCKED', 'NONE', etc.)
            score: Confidence score
            
        Returns:
            Human-readable attack type string
        """
        if prediction == 'MALICIOUS':
            if score >= 0.95:
                return 'High Confidence Threat'
            elif score >= 0.85:
                return 'Network Anomaly'
            elif score >= 0.70:
                return 'Suspicious Flow'
            else:
                return 'Potential Threat'
        elif prediction == 'BENIGN':
            return 'Benign Traffic'
        else:
            if score >= 0.85:
                return 'Anomalous Behavior'
            elif score >= 0.50:
                return 'Unusual Pattern'
            else:
                return 'Normal Traffic'
