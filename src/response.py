"""
Automated response actions for AI-Powered Threat Detection System.

Implements IP blocking via Windows Defender Firewall, audit logging to SQLite,
and email alerting. All actions are reversible and respect a whitelist.

REQUIRES ADMINISTRATOR PRIVILEGES to modify Windows Firewall rules.
"""

import logging
import sqlite3
import subprocess
import threading
import time
import smtplib
import ctypes
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class BlockRecord:
    """Record of a firewall block action."""
    ip: str
    timestamp: datetime
    expiry: datetime
    reason: str
    actor: str
    score: Optional[float] = None


class ResponseManager:
    """
    Manages automated response actions: IP blocking, alerting, and audit logging.
    
    Uses Windows Defender Firewall (via netsh or PowerShell) to block malicious IPs.
    Maintains an SQLite audit log of all actions. Supports TTL-based auto-expiry
    via background cleanup thread.
    """
    
    def __init__(
        self,
        db_path: str,
        whitelist: List[str],
        firewall_rule_prefix: str = "AIThreatDefense_Block_",
        cleanup_interval: int = 300
    ):
        """
        Initialize the response manager.
        
        Args:
            db_path: Path to SQLite database for audit logging
            whitelist: List of IP addresses that must never be blocked
            firewall_rule_prefix: Prefix for firewall rule names
            cleanup_interval: Seconds between cleanup runs
            
        Raises:
            PermissionError: If not running with administrator privileges
            RuntimeError: If database initialization fails
        """
        # Check for admin privileges first
        if not self._is_admin():
            raise PermissionError(
                "Administrator privileges required to modify Windows Firewall. "
                "Run this program as Administrator."
            )
        
        self.db_path = Path(db_path)
        self.whitelist = set(whitelist)
        self.firewall_rule_prefix = firewall_rule_prefix
        self.cleanup_interval = cleanup_interval
        
        # Ensure database directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # Start cleanup thread
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()
        self._start_cleanup_thread()
        
        logger.info(
            f"Initialized ResponseManager (whitelist: {len(self.whitelist)} IPs, "
            f"cleanup interval: {cleanup_interval}s)"
        )
    
    @staticmethod
    def _is_admin() -> bool:
        """
        Check if running with Administrator privileges on Windows.
        
        Returns:
            True if running as admin, False otherwise
        """
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logger.warning(f"Failed to check admin status: {e}")
            return False
    
    def _init_database(self) -> None:
        """
        Initialize SQLite database with required tables.
        
        Creates:
        - audit_log: All block/unblock actions
        - active_blocks: Currently active firewall blocks with expiry
        - flow_scores: All scored flows for analysis
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT,
                    score REAL,
                    details TEXT
                )
            """)
            
            # Active blocks table (for TTL management)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS active_blocks (
                    ip TEXT PRIMARY KEY,
                    blocked_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    reason TEXT,
                    actor TEXT,
                    score REAL
                )
            """)
            
            # Flow scores table (for analysis)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flow_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dest_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dest_port INTEGER,
                    proto TEXT,
                    score REAL NOT NULL,
                    prediction TEXT,
                    action_taken TEXT
                )
            """)
            
            # Create indices for performance
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_timestamp "
                "ON audit_log(timestamp)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_flow_timestamp "
                "ON flow_scores(timestamp)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_flow_src_ip "
                "ON flow_scores(src_ip)"
            )
            
            conn.commit()
            conn.close()
            
            logger.info(f"Database initialized at {self.db_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise RuntimeError(f"Database initialization failed: {e}")
    
    def _execute_db_query(
        self,
        query: str,
        params: tuple = (),
        fetch: bool = False
    ) -> Optional[List[tuple]]:
        """
        Execute a database query with error handling.
        
        Args:
            query: SQL query string
            params: Query parameters
            fetch: Whether to fetch and return results
            
        Returns:
            Query results if fetch=True, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            result = None
            if fetch:
                result = cursor.fetchall()
            
            conn.commit()
            conn.close()
            return result
            
        except Exception as e:
            logger.error(f"Database error: {e} | Query: {query}")
            return None
    
    def _log_audit(
        self,
        action: str,
        ip: str,
        actor: str,
        reason: Optional[str] = None,
        score: Optional[float] = None,
        details: Optional[str] = None
    ) -> None:
        """
        Write an entry to the audit log.
        
        Args:
            action: Action type (e.g., 'BLOCK', 'UNBLOCK', 'ALERT')
            ip: IP address involved
            actor: Who initiated the action ('system' or username)
            reason: Human-readable reason
            score: ML model confidence score if applicable
            details: Additional details (JSON string or text)
        """
        timestamp = datetime.utcnow().isoformat()
        
        self._execute_db_query(
            """
            INSERT INTO audit_log (timestamp, action, ip, actor, reason, score, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp, action, ip, actor, reason, score, details)
        )
        
        logger.info(
            f"AUDIT: {action} | IP={ip} | Actor={actor} | "
            f"Reason={reason} | Score={score}"
        )
    
    def log_flow_score(
        self,
        src_ip: str,
        dest_ip: str,
        score: float,
        prediction: str,
        action_taken: str,
        src_port: Optional[int] = None,
        dest_port: Optional[int] = None,
        proto: Optional[str] = None
    ) -> None:
        """
        Log a scored flow to the database for analysis.
        
        Args:
            src_ip: Source IP address
            dest_ip: Destination IP address
            score: Model confidence score
            prediction: Model prediction class
            action_taken: What action was taken ('BLOCKED', 'ALERTED', 'NONE')
            src_port: Source port
            dest_port: Destination port
            proto: Protocol (TCP/UDP/etc)
        """
        timestamp = datetime.utcnow().isoformat()
        
        self._execute_db_query(
            """
            INSERT INTO flow_scores 
            (timestamp, src_ip, dest_ip, src_port, dest_port, proto, score, prediction, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp, src_ip, dest_ip, src_port, dest_port, proto, score, prediction, action_taken)
        )
    
    def is_whitelisted(self, ip: str) -> bool:
        """
        Check if an IP is on the whitelist.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if whitelisted, False otherwise
        """
        return ip in self.whitelist
    
    def is_blocked(self, ip: str) -> bool:
        """
        Check if an IP is currently blocked.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if blocked, False otherwise
        """
        result = self._execute_db_query(
            "SELECT 1 FROM active_blocks WHERE ip = ?",
            (ip,),
            fetch=True
        )
        return bool(result)
    
    def block_ip(
        self,
        ip: str,
        reason: str,
        ttl: int = 3600,
        actor: str = "system",
        score: Optional[float] = None
    ) -> bool:
        """
        Block an IP address using Windows Firewall.
        
        Creates a firewall rule to block all inbound and outbound traffic
        from/to the specified IP. The block is recorded with an expiry time.
        
        Args:
            ip: IP address to block
            reason: Human-readable reason for the block
            ttl: Time-to-live in seconds (how long to keep the block)
            actor: Who initiated the block ('system' or username)
            score: ML model confidence score if applicable
            
        Returns:
            True if block succeeded, False otherwise
        """
        # Check whitelist
        if self.is_whitelisted(ip):
            logger.warning(
                f"Attempted to block whitelisted IP {ip}. Ignoring."
            )
            self._log_audit('BLOCK_DENIED', ip, actor, 
                          'IP is whitelisted', score)
            return False
        
        # Check if already blocked
        if self.is_blocked(ip):
            logger.info(f"IP {ip} is already blocked. Updating expiry.")
            return self._update_block_expiry(ip, ttl)
        
        # Create firewall rule
        rule_name = f"{self.firewall_rule_prefix}{ip.replace('.', '_').replace(':', '_')}"
        
        # Use netsh as it's more reliable than PowerShell for automation
        commands = [
            # Block inbound
            [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_IN',
                'dir=in',
                'action=block',
                f'remoteip={ip}',
                'enable=yes'
            ],
            # Block outbound
            [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_OUT',
                'dir=out',
                'action=block',
                f'remoteip={ip}',
                'enable=yes'
            ]
        ]
        
        success = True
        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode != 0:
                    logger.error(
                        f"Firewall command failed: {' '.join(cmd)} | "
                        f"Error: {result.stderr}"
                    )
                    success = False
                    
            except subprocess.TimeoutExpired:
                logger.error(f"Firewall command timed out: {' '.join(cmd)}")
                success = False
            except Exception as e:
                logger.error(f"Error executing firewall command: {e}")
                success = False
        
        if success:
            # Record the block
            blocked_at = datetime.utcnow()
            expires_at = blocked_at + timedelta(seconds=ttl)
            
            self._execute_db_query(
                """
                INSERT INTO active_blocks (ip, blocked_at, expires_at, reason, actor, score)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (ip, blocked_at.isoformat(), expires_at.isoformat(), 
                 reason, actor, score)
            )
            
            self._log_audit('BLOCK', ip, actor, reason, score, 
                          f"TTL={ttl}s, Expires={expires_at.isoformat()}")
            
            logger.warning(
                f"BLOCKED IP: {ip} | Reason: {reason} | "
                f"Score: {score} | TTL: {ttl}s"
            )
        
        return success
    
    def _update_block_expiry(self, ip: str, additional_ttl: int) -> bool:
        """
        Extend the expiry time of an existing block.
        
        Args:
            ip: IP address
            additional_ttl: Seconds to add to current expiry
            
        Returns:
            True if updated, False otherwise
        """
        new_expiry = datetime.utcnow() + timedelta(seconds=additional_ttl)
        
        self._execute_db_query(
            "UPDATE active_blocks SET expires_at = ? WHERE ip = ?",
            (new_expiry.isoformat(), ip)
        )
        
        logger.info(f"Extended block for {ip} to {new_expiry.isoformat()}")
        return True
    
    def unblock_ip(self, ip: str, actor: str = "admin") -> bool:
        """
        Manually unblock an IP address.
        
        Removes the firewall rules and deletes the block record.
        
        Args:
            ip: IP address to unblock
            actor: Who initiated the unblock (username)
            
        Returns:
            True if unblock succeeded, False otherwise
        """
        if not self.is_blocked(ip):
            logger.info(f"IP {ip} is not blocked. Nothing to do.")
            return True
        
        # Remove firewall rules
        rule_name = f"{self.firewall_rule_prefix}{ip.replace('.', '_').replace(':', '_')}"
        
        commands = [
            [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}_IN'
            ],
            [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}_OUT'
            ]
        ]
        
        success = True
        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # netsh returns 0 even if rule doesn't exist, which is fine
                if result.returncode != 0 and "No rules match" not in result.stderr:
                    logger.warning(
                        f"Firewall delete warning: {result.stderr}"
                    )
                    
            except Exception as e:
                logger.error(f"Error removing firewall rule: {e}")
                success = False
        
        # Remove from active_blocks regardless (cleanup)
        self._execute_db_query(
            "DELETE FROM active_blocks WHERE ip = ?",
            (ip,)
        )
        
        self._log_audit('UNBLOCK', ip, actor, "Manual unblock")
        
        logger.info(f"UNBLOCKED IP: {ip} | Actor: {actor}")
        
        return success
    
    def cleanup_expired_blocks(self) -> int:
        """
        Remove firewall rules for expired blocks.
        
        This should be called periodically by the cleanup thread.
        
        Returns:
            Number of blocks removed
        """
        now = datetime.utcnow().isoformat()
        
        # Find expired blocks
        expired = self._execute_db_query(
            "SELECT ip, expires_at FROM active_blocks WHERE expires_at <= ?",
            (now,),
            fetch=True
        )
        
        if not expired:
            return 0
        
        count = 0
        for ip, expires_at in expired:
            logger.info(f"Removing expired block for {ip} (expired: {expires_at})")
            if self.unblock_ip(ip, actor="system_cleanup"):
                count += 1
        
        logger.info(f"Cleanup: removed {count} expired blocks")
        return count
    
    def _cleanup_loop(self) -> None:
        """Background thread loop for periodic cleanup."""
        logger.info(f"Cleanup thread started (interval: {self.cleanup_interval}s)")
        
        while not self._stop_cleanup.is_set():
            try:
                self.cleanup_expired_blocks()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}", exc_info=True)
            
            # Sleep with interruptible wait
            self._stop_cleanup.wait(self.cleanup_interval)
        
        logger.info("Cleanup thread stopped")
    
    def _start_cleanup_thread(self) -> None:
        """Start the background cleanup thread."""
        if self._cleanup_thread is not None:
            logger.warning("Cleanup thread already running")
            return
        
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="BlockCleanup"
        )
        self._cleanup_thread.start()
    
    def send_alert(
        self,
        ip: str,
        score: float,
        event: Dict[str, Any],
        smtp_config: Dict[str, Any]
    ) -> bool:
        """
        Send an email alert about a detected threat.
        
        Args:
            ip: Source IP of the threat
            score: Model confidence score
            event: Suricata event dictionary
            smtp_config: SMTP configuration dict with keys:
                        server, port, use_tls, username, password, from, to
            
        Returns:
            True if alert sent successfully, False otherwise
        """
        if not smtp_config.get('enabled', False):
            logger.debug("SMTP alerts disabled, skipping email")
            return False
        
        try:
            # Build email content
            subject = f"[THREAT DETECTED] Malicious activity from {ip}"
            
            body = f"""
AI-Powered Threat Detection Alert

THREAT DETECTED
Source IP: {ip}
Confidence Score: {score:.4f}
Detection Time: {datetime.utcnow().isoformat()}

EVENT DETAILS:
Protocol: {event.get('proto', 'unknown')}
Source Port: {event.get('src_port', 'unknown')}
Destination: {event.get('dest_ip', 'unknown')}:{event.get('dest_port', 'unknown')}

Flow Statistics:
- Packets to server: {event.get('flow', {}).get('pkts_toserver', 0)}
- Packets to client: {event.get('flow', {}).get('pkts_toclient', 0)}
- Bytes to server: {event.get('flow', {}).get('bytes_toserver', 0)}
- Bytes to client: {event.get('flow', {}).get('bytes_toclient', 0)}

ACTION TAKEN: IP address has been automatically blocked by Windows Firewall.

This is an automated alert from the AI-Powered Threat Detection & Response System.
Debre Berhan University - Department of IT
"""
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = smtp_config['from']
            msg['To'] = ', '.join(smtp_config['to'])
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            # Send via SMTP
            server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
            
            if smtp_config.get('use_tls', True):
                server.starttls()
            
            if smtp_config.get('username') and smtp_config.get('password'):
                server.login(smtp_config['username'], smtp_config['password'])
            
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Alert email sent to {smtp_config['to']}")
            self._log_audit('ALERT_SENT', ip, 'system', 
                          f"Email sent (score={score:.4f})", score)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send alert email: {e}", exc_info=True)
            return False
    
    def get_active_blocks(self) -> List[BlockRecord]:
        """
        Get list of currently active blocks.
        
        Returns:
            List of BlockRecord objects
        """
        rows = self._execute_db_query(
            """
            SELECT ip, blocked_at, expires_at, reason, actor, score
            FROM active_blocks
            ORDER BY blocked_at DESC
            """,
            fetch=True
        )
        
        if not rows:
            return []
        
        records = []
        for row in rows:
            records.append(BlockRecord(
                ip=row[0],
                timestamp=datetime.fromisoformat(row[1]),
                expiry=datetime.fromisoformat(row[2]),
                reason=row[3],
                actor=row[4],
                score=row[5]
            ))
        
        return records
    
    def shutdown(self) -> None:
        """Clean shutdown of the response manager."""
        logger.info("Shutting down ResponseManager")
        
        # Stop cleanup thread
        if self._cleanup_thread:
            self._stop_cleanup.set()
            self._cleanup_thread.join(timeout=5)
        
        logger.info("ResponseManager shutdown complete")


if __name__ == '__main__':
    # Standalone test
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("Testing ResponseManager (requires Administrator privileges)")
    
    try:
        manager = ResponseManager(
            db_path="data/test_threat_defense.db",
            whitelist=["127.0.0.1", "::1", "192.168.1.1"]
        )
        
        # Test block (use a non-routable test IP)
        test_ip = "192.0.2.1"  # TEST-NET-1 (RFC 5737)
        
        print(f"\nTesting block of {test_ip}...")
        success = manager.block_ip(
            test_ip,
            reason="Test block",
            ttl=60,
            score=0.95
        )
        print(f"Block result: {'SUCCESS' if success else 'FAILED'}")
        
        print(f"\nChecking if {test_ip} is blocked...")
        print(f"Is blocked: {manager.is_blocked(test_ip)}")
        
        print(f"\nActive blocks:")
        for block in manager.get_active_blocks():
            print(f"  - {block.ip}: {block.reason} (expires: {block.expiry})")
        
        print(f"\nUnblocking {test_ip}...")
        manager.unblock_ip(test_ip, actor="test_user")
        print(f"Is blocked: {manager.is_blocked(test_ip)}")
        
        manager.shutdown()
        print("\nTest complete!")
        
    except PermissionError as e:
        print(f"\nERROR: {e}")
        print("Please run this script as Administrator.")
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
