"""
Suricata EVE JSON log watcher for Windows.

Tails the Suricata eve.json file and yields parsed JSON events as they arrive.
Handles partial/interrupted line writes gracefully and works with Windows file locking.
"""

import json
import time
import logging
from pathlib import Path
from typing import Generator, Dict, Any, Optional
from datetime import datetime


logger = logging.getLogger(__name__)


class SuricataWatcher:
    """
    Watches Suricata EVE JSON log file and yields events in real-time.
    
    This class implements a robust file-tailing mechanism that works on Windows,
    handling file rotation, partial writes, and the case where Suricata hasn't
    created the log file yet.
    """
    
    def __init__(
        self,
        eve_json_path: str,
        event_types: Optional[list[str]] = None,
        poll_interval: float = 0.1,
        max_line_buffer: int = 10000
    ):
        """
        Initialize the Suricata watcher.
        
        Args:
            eve_json_path: Path to Suricata eve.json log file
            event_types: List of event types to yield (e.g., ['flow', 'alert']).
                        If None, yield all event types.
            poll_interval: Seconds to wait between file checks
            max_line_buffer: Maximum characters to buffer for incomplete lines
            
        Raises:
            ValueError: If eve_json_path parent directory doesn't exist
        """
        self.eve_json_path = Path(eve_json_path)
        self.event_types = set(event_types) if event_types else None
        self.poll_interval = poll_interval
        self.max_line_buffer = max_line_buffer
        
        # Validate parent directory exists
        if not self.eve_json_path.parent.exists():
            raise ValueError(
                f"Log directory does not exist: {self.eve_json_path.parent}"
            )
        
        self._file_handle: Optional[Any] = None
        self._file_inode: Optional[int] = None
        self._partial_line: str = ""
        self._events_yielded: int = 0
        self._errors_encountered: int = 0
        
        logger.info(
            f"Initialized SuricataWatcher for {self.eve_json_path}"
            f"{f' (filtering: {self.event_types})' if self.event_types else ''}"
        )
    
    def _wait_for_file(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for the eve.json file to be created.
        
        Args:
            timeout: Maximum seconds to wait. None = wait indefinitely.
            
        Returns:
            True if file exists, False if timeout reached
        """
        start_time = time.time()
        
        while not self.eve_json_path.exists():
            if timeout and (time.time() - start_time) > timeout:
                return False
            
            logger.debug(
                f"Waiting for {self.eve_json_path} to be created..."
            )
            time.sleep(self.poll_interval)
        
        return True
    
    def _open_file(self) -> None:
        """
        Open the eve.json file and seek to the end.
        
        On Windows, we open in 'r' mode with buffering disabled to avoid
        conflicts with Suricata's write operations.
        """
        if self._file_handle:
            self._file_handle.close()
        
        try:
            # Open in text mode, binary=False for line-based reading
            # buffering=1 means line buffering
            self._file_handle = open(
                self.eve_json_path,
                'r',
                encoding='utf-8',
                buffering=1
            )
            
            # Start at the end for new events only
            # To process historical events, seek to 0 instead
            self._file_handle.seek(0, 2)  # 2 = SEEK_END
            
            # Track file identity to detect rotation
            stat = self.eve_json_path.stat()
            self._file_inode = stat.st_ino
            
            logger.info(f"Opened {self.eve_json_path} for tailing")
            
        except PermissionError as e:
            logger.error(f"Permission denied opening {self.eve_json_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Error opening {self.eve_json_path}: {e}")
            raise
    
    def _check_file_rotation(self) -> bool:
        """
        Check if the log file has been rotated.
        
        Returns:
            True if file was rotated, False otherwise
        """
        try:
            if not self.eve_json_path.exists():
                return True
            
            stat = self.eve_json_path.stat()
            if stat.st_ino != self._file_inode:
                logger.info("Detected log rotation")
                return True
            
            # Check if file was truncated (size smaller than current position)
            if self._file_handle and stat.st_size < self._file_handle.tell():
                logger.info("Detected log truncation")
                return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Error checking file rotation: {e}")
            return True
    
    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a JSON line from the eve.json log.
        
        Args:
            line: Raw JSON line
            
        Returns:
            Parsed event dictionary, or None if parsing failed
        """
        line = line.strip()
        if not line:
            return None
        
        try:
            event = json.loads(line)
            
            # Filter by event type if specified
            if self.event_types:
                event_type = event.get('event_type')
                if event_type not in self.event_types:
                    return None
            
            self._events_yielded += 1
            return event
            
        except json.JSONDecodeError as e:
            self._errors_encountered += 1
            logger.warning(
                f"Failed to parse JSON line (error #{self._errors_encountered}): "
                f"{line[:100]}... | Error: {e}"
            )
            return None
    
    def _read_new_lines(self) -> Generator[str, None, None]:
        """
        Read new complete lines from the file.
        
        Handles partial line writes by buffering incomplete lines.
        
        Yields:
            Complete lines from the file
        """
        if not self._file_handle:
            return
        
        while True:
            # Read available data
            chunk = self._file_handle.read()
            
            if not chunk:
                # No new data
                break
            
            # Combine with any partial line from previous read
            data = self._partial_line + chunk
            
            # Split into lines
            lines = data.split('\n')
            
            # Last element might be incomplete
            self._partial_line = lines[-1]
            
            # Check if partial line buffer is getting too large
            if len(self._partial_line) > self.max_line_buffer:
                logger.warning(
                    f"Partial line buffer exceeded {self.max_line_buffer} chars, "
                    f"discarding: {self._partial_line[:100]}..."
                )
                self._partial_line = ""
            
            # Yield complete lines
            for line in lines[:-1]:
                yield line
    
    def watch(
        self,
        start_timeout: Optional[float] = 30.0,
        stop_on_error: bool = False
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Watch the EVE JSON file and yield events as they arrive.
        
        This is the main method to use. It handles file creation, rotation,
        and graceful error recovery.
        
        Args:
            start_timeout: Max seconds to wait for file creation (None = indefinite)
            stop_on_error: If True, raise exceptions. If False, log and continue.
            
        Yields:
            Parsed Suricata event dictionaries
            
        Raises:
            FileNotFoundError: If file doesn't exist after timeout
            Exception: If stop_on_error=True and an error occurs
            
        Example:
            >>> watcher = SuricataWatcher('/path/to/eve.json', event_types=['flow'])
            >>> for event in watcher.watch():
            ...     print(f"Flow from {event['src_ip']} to {event['dest_ip']}")
        """
        # Wait for file to exist
        if not self.eve_json_path.exists():
            logger.info(
                f"Waiting for {self.eve_json_path} to be created "
                f"(timeout: {start_timeout}s)..."
            )
            if not self._wait_for_file(timeout=start_timeout):
                raise FileNotFoundError(
                    f"Suricata log file not found after {start_timeout}s: "
                    f"{self.eve_json_path}"
                )
        
        # Open the file
        self._open_file()
        
        logger.info("Starting EVE JSON watch loop")
        
        try:
            while True:
                # Check for file rotation
                if self._check_file_rotation():
                    logger.info("Reopening file after rotation/truncation")
                    self._open_file()
                
                # Read and parse new lines
                for line in self._read_new_lines():
                    event = self._parse_line(line)
                    if event:
                        yield event
                
                # Brief sleep before next poll
                time.sleep(self.poll_interval)
                
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, stopping watcher")
            raise
            
        except Exception as e:
            logger.error(f"Error in watch loop: {e}", exc_info=True)
            if stop_on_error:
                raise
            
        finally:
            self.close()
    
    def close(self) -> None:
        """Close the file handle and cleanup resources."""
        if self._file_handle:
            try:
                self._file_handle.close()
                logger.info(
                    f"Closed watcher (events yielded: {self._events_yielded}, "
                    f"parse errors: {self._errors_encountered})"
                )
            except Exception as e:
                logger.warning(f"Error closing file handle: {e}")
            finally:
                self._file_handle = None
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get statistics about the watcher.
        
        Returns:
            Dictionary with events_yielded and errors_encountered counts
        """
        return {
            'events_yielded': self._events_yielded,
            'errors_encountered': self._errors_encountered
        }
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False


def main():
    """
    Standalone test function for the watcher.
    
    Run this module directly to test the watcher against your Suricata installation.
    """
    import sys
    
    # Setup basic logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Get path from command line or use default
    eve_path = sys.argv[1] if len(sys.argv) > 1 else \
               "C:\\Program Files\\Suricata\\log\\eve.json"
    
    logger.info(f"Testing SuricataWatcher with {eve_path}")
    logger.info("Press Ctrl+C to stop")
    
    try:
        watcher = SuricataWatcher(
            eve_path,
            event_types=['flow', 'alert']  # Only watch flow and alert events
        )
        
        for event in watcher.watch(start_timeout=60.0):
            event_type = event.get('event_type', 'unknown')
            timestamp = event.get('timestamp', 'no-timestamp')
            
            if event_type == 'flow':
                src = f"{event.get('src_ip', '?')}:{event.get('src_port', '?')}"
                dst = f"{event.get('dest_ip', '?')}:{event.get('dest_port', '?')}"
                proto = event.get('proto', '?')
                logger.info(f"FLOW: {src} -> {dst} ({proto})")
                
            elif event_type == 'alert':
                signature = event.get('alert', {}).get('signature', 'unknown')
                src_ip = event.get('src_ip', '?')
                logger.warning(f"ALERT: {signature} from {src_ip}")
                
            else:
                logger.info(f"EVENT: {event_type} at {timestamp}")
    
    except KeyboardInterrupt:
        logger.info("Stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
