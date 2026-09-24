"""
Process Resolver Module

Maps network connections (IP:Port) to process names and PIDs using
netstat and PowerShell on Windows. Enriches flow data with application
information for better threat context.
"""

import subprocess
import logging
import re
from typing import Dict, Optional, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import time


logger = logging.getLogger(__name__)


class ProcessResolver:
    """
    Resolves network connections to process names using netstat.
    
    Caches results to minimize performance impact of repeated subprocess calls.
    """
    
    def __init__(self, cache_ttl: int = 30):
        """
        Initialize the process resolver.
        
        Args:
            cache_ttl: Cache time-to-live in seconds (default: 30s)
        """
        self.cache_ttl = cache_ttl
        self.cache: Dict[str, Tuple[str, str, datetime]] = {}  # key -> (process, pid, timestamp)
        self.lock = threading.Lock()
        self.last_full_scan = None
        self.connection_table: Dict[str, Tuple[str, str]] = {}  # local_addr:port -> (process, pid)
        
        logger.info(f"ProcessResolver initialized with cache TTL: {cache_ttl}s")
    
    def get_process_for_connection(
        self,
        local_ip: str,
        local_port: Optional[int] = None,
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
        protocol: str = "TCP"
    ) -> Optional[Dict[str, str]]:
        """
        Get process information for a network connection.
        
        Args:
            local_ip: Local IP address
            local_port: Local port number
            remote_ip: Remote IP address (optional)
            remote_port: Remote port number (optional)
            protocol: Protocol (TCP/UDP)
            
        Returns:
            Dictionary with 'process', 'pid', or None if not found
        """
        # Build cache key
        cache_key = f"{local_ip}:{local_port}:{remote_ip}:{remote_port}:{protocol}"
        
        # Check cache
        with self.lock:
            if cache_key in self.cache:
                process, pid, timestamp = self.cache[cache_key]
                age = (datetime.now() - timestamp).total_seconds()
                
                if age < self.cache_ttl:
                    logger.debug(f"Cache hit for {cache_key}: {process} (PID: {pid})")
                    return {'process': process, 'pid': pid}
                else:
                    # Expired
                    del self.cache[cache_key]
        
        # Not in cache or expired - refresh connection table if needed
        if self._should_refresh_table():
            self._refresh_connection_table()
        
        # Look up in connection table
        result = self._lookup_connection(local_ip, local_port, remote_ip, remote_port, protocol)
        
        # Cache the result
        if result:
            with self.lock:
                self.cache[cache_key] = (result['process'], result['pid'], datetime.now())
        
        return result
    
    def _should_refresh_table(self) -> bool:
        """Check if connection table needs refresh."""
        if self.last_full_scan is None:
            return True
        
        age = (datetime.now() - self.last_full_scan).total_seconds()
        return age > self.cache_ttl
    
    def _refresh_connection_table(self) -> None:
        """
        Refresh the connection table using netstat.
        
        Runs netstat -abno to get all connections with process names.
        Parses output into a lookup table.
        """
        try:
            logger.debug("Refreshing connection table with netstat...")
            
            # Run netstat -abno (requires admin privileges for -b)
            # -a: all connections
            # -n: numeric addresses (no DNS lookup)
            # -o: show owning PID
            # -b: show process name (requires admin)
            
            cmd = ["netstat", "-ano"]  # Skip -b for now as it's slow
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )
            
            if result.returncode != 0:
                logger.error(f"netstat failed: {result.stderr}")
                return
            
            # Parse netstat output
            connections = self._parse_netstat_output(result.stdout)
            
            with self.lock:
                self.connection_table = connections
                self.last_full_scan = datetime.now()
            
            logger.debug(f"Connection table refreshed: {len(connections)} entries")
            
        except subprocess.TimeoutExpired:
            logger.error("netstat command timed out")
        except Exception as e:
            logger.error(f"Error refreshing connection table: {e}", exc_info=True)
    
    def _parse_netstat_output(self, output: str) -> Dict[str, Tuple[str, str]]:
        """
        Parse netstat output into connection lookup table.
        
        Args:
            output: netstat command output
            
        Returns:
            Dictionary mapping "local_addr:port" to (process_name, pid)
        """
        connections = {}
        
        # Netstat output format:
        # Proto  Local Address          Foreign Address        State           PID
        # TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
        # TCP    192.168.1.10:50123     52.2.211.10:443        ESTABLISHED     5678
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Skip header lines
            if not line or 'Proto' in line or 'Active' in line:
                continue
            
            # Parse line
            parts = line.split()
            
            if len(parts) < 5:
                continue
            
            try:
                proto = parts[0].upper()
                local_addr = parts[1]
                remote_addr = parts[2]
                
                # Find PID (last numeric field)
                pid = None
                for part in reversed(parts):
                    if part.isdigit():
                        pid = part
                        break
                
                if not pid:
                    continue
                
                # Get process name from PID
                process_name = self._get_process_name_from_pid(pid)
                
                # Store in table
                key = f"{proto}:{local_addr}:{remote_addr}"
                connections[key] = (process_name, pid)
                
                # Also store simplified key (just local addr:port)
                local_key = f"{proto}:{local_addr}"
                if local_key not in connections:
                    connections[local_key] = (process_name, pid)
                
            except Exception as e:
                logger.debug(f"Error parsing netstat line '{line}': {e}")
                continue
        
        return connections
    
    def _get_process_name_from_pid(self, pid: str) -> str:
        """
        Get process name from PID using PowerShell.
        
        Args:
            pid: Process ID
            
        Returns:
            Process name or "Unknown"
        """
        try:
            # Use PowerShell Get-Process
            cmd = [
                "powershell", "-Command",
                f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).ProcessName"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            
        except Exception as e:
            logger.debug(f"Error getting process name for PID {pid}: {e}")
        
        return "Unknown"
    
    def _lookup_connection(
        self,
        local_ip: str,
        local_port: Optional[int],
        remote_ip: Optional[str],
        remote_port: Optional[int],
        protocol: str
    ) -> Optional[Dict[str, str]]:
        """
        Look up connection in the connection table.
        
        Tries multiple key formats to find a match.
        """
        with self.lock:
            # Try exact match first
            if local_port and remote_ip and remote_port:
                key = f"{protocol.upper()}:{local_ip}:{local_port}:{remote_ip}:{remote_port}"
                if key in self.connection_table:
                    process, pid = self.connection_table[key]
                    return {'process': process, 'pid': pid}
            
            # Try local address only
            if local_port:
                key = f"{protocol.upper()}:{local_ip}:{local_port}"
                if key in self.connection_table:
                    process, pid = self.connection_table[key]
                    return {'process': process, 'pid': pid}
            
            # Try wildcard local address (0.0.0.0 or [::])
            if local_port:
                for wildcard in ["0.0.0.0", "[::]", "*"]:
                    key = f"{protocol.upper()}:{wildcard}:{local_port}"
                    if key in self.connection_table:
                        process, pid = self.connection_table[key]
                        return {'process': process, 'pid': pid}
        
        logger.debug(f"No process found for {local_ip}:{local_port}")
        return None
    
    def clear_cache(self) -> None:
        """Clear the process resolution cache."""
        with self.lock:
            self.cache.clear()
            self.connection_table.clear()
            self.last_full_scan = None
        logger.info("Process resolver cache cleared")
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get resolver statistics.
        
        Returns:
            Dictionary with cache size, connection table size
        """
        with self.lock:
            return {
                'cache_size': len(self.cache),
                'connection_table_size': len(self.connection_table),
                'last_scan_age': int((datetime.now() - self.last_full_scan).total_seconds())
                    if self.last_full_scan else -1
            }
