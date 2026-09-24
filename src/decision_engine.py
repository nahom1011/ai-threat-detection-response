"""
AI-Powered Threat Detection Decision Engine.

Main detection loop that integrates Suricata event watching, feature extraction,
ML-based prediction, and automated response actions. Tracks performance metrics
and logs all scored flows.

This is the core service component of the threat detection system.
"""

import logging
import sys
import signal
import time
import joblib
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
import numpy as np

from config import load_config, Config
from suricata_watcher import SuricataWatcher
from feature_extractor import FeatureExtractor
from response import ResponseManager
from process_resolver import ProcessResolver


# Setup logging
logger = logging.getLogger(__name__)


class PerformanceTracker:
    """Tracks processing performance metrics."""
    
    def __init__(self, warn_threshold_ms: int = 100):
        """
        Initialize performance tracker.
        
        Args:
            warn_threshold_ms: Warn if processing takes longer than this
        """
        self.warn_threshold_ms = warn_threshold_ms
        self.total_flows = 0
        self.total_predictions = 0
        self.total_blocks = 0
        self.total_alerts = 0
        self.total_latency_ms = 0.0
        self.max_latency_ms = 0.0
        self.warnings = 0
        self.start_time = datetime.utcnow()
    
    def record_flow(self, latency_ms: float) -> None:
        """
        Record a processed flow.
        
        Args:
            latency_ms: Processing time in milliseconds
        """
        self.total_flows += 1
        self.total_latency_ms += latency_ms
        
        if latency_ms > self.max_latency_ms:
            self.max_latency_ms = latency_ms
        
        if latency_ms > self.warn_threshold_ms:
            self.warnings += 1
            logger.warning(
                f"Flow processing latency exceeded threshold: "
                f"{latency_ms:.2f}ms > {self.warn_threshold_ms}ms"
            )
    
    def record_prediction(self, is_malicious: bool) -> None:
        """Record a prediction."""
        self.total_predictions += 1
        if is_malicious:
            self.total_blocks += 1
    
    def record_alert(self) -> None:
        """Record an alert sent."""
        self.total_alerts += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get performance statistics.
        
        Returns:
            Dictionary with performance metrics
        """
        runtime = (datetime.utcnow() - self.start_time).total_seconds()
        avg_latency = (self.total_latency_ms / self.total_flows 
                      if self.total_flows > 0 else 0.0)
        
        return {
            'runtime_seconds': runtime,
            'total_flows': self.total_flows,
            'total_predictions': self.total_predictions,
            'total_blocks': self.total_blocks,
            'total_alerts': self.total_alerts,
            'avg_latency_ms': avg_latency,
            'max_latency_ms': self.max_latency_ms,
            'latency_warnings': self.warnings,
            'flows_per_second': self.total_flows / runtime if runtime > 0 else 0.0
        }
    
    def log_stats(self) -> None:
        """Log current statistics."""
        stats = self.get_stats()
        logger.info(
            f"STATS: Flows={stats['total_flows']} | "
            f"Predictions={stats['total_predictions']} | "
            f"Blocks={stats['total_blocks']} | "
            f"Alerts={stats['total_alerts']} | "
            f"AvgLatency={stats['avg_latency_ms']:.2f}ms | "
            f"MaxLatency={stats['max_latency_ms']:.2f}ms | "
            f"FlowRate={stats['flows_per_second']:.2f}/s"
        )


class DecisionEngine:
    """
    Main decision engine for threat detection.
    
    Orchestrates the entire detection pipeline:
    1. Watch Suricata EVE JSON events
    2. Extract features from flow events
    3. Run ML model prediction
    4. Take response actions if confidence >= threshold
    5. Log all activity for audit and analysis
    """
    
    def __init__(self, config: Config):
        """
        Initialize the decision engine.
        
        Args:
            config: System configuration object
            
        Raises:
            FileNotFoundError: If model files not found
            RuntimeError: If initialization fails
        """
        self.config = config
        self._running = False
        self._shutdown_requested = False
        
        # Load ML model
        logger.info("Loading ML model...")
        model_path = Path(config.model.xgboost_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        try:
            self.model = joblib.load(model_path)
            logger.info(f"Loaded XGBoost model from {model_path}")
        except Exception as e:
            raise RuntimeError(f"Failed to load model: {e}")
        
        # Initialize feature extractor with scaler
        logger.info("Initializing feature extractor...")
        scaler_path = Path(config.model.scaler_path)
        if not scaler_path.exists():
            raise FileNotFoundError(f"Scaler file not found: {scaler_path}")
        
        self.extractor = FeatureExtractor(scaler_path=str(scaler_path))
        
        # Validate model compatibility
        if not self.extractor.validate_model_compatibility(str(model_path)):
            logger.error(
                "Model may be incompatible with feature extractor! "
                "Verify feature columns match training data."
            )
        
        # Initialize response manager
        logger.info("Initializing response manager...")
        self.response = ResponseManager(
            db_path=config.database.path,
            whitelist=config.response.whitelist,
            firewall_rule_prefix=config.response.firewall_rule_prefix,
            cleanup_interval=config.response.cleanup_interval
        )
        
        # Initialize Suricata watcher
        logger.info("Initializing Suricata watcher...")
        self.watcher = SuricataWatcher(
            eve_json_path=config.suricata.eve_json_path,
            event_types=['flow']  # Only watch flow events
        )
        
        # Initialize process resolver
        logger.info("Initializing process resolver...")
        self.process_resolver = ProcessResolver(cache_ttl=30)
        
        # Performance tracking
        self.perf = PerformanceTracker(
            warn_threshold_ms=config.performance.max_flow_latency_ms
        )
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info("Decision engine initialized successfully")
    
    def _signal_handler(self, signum, frame) -> None:
        """
        Handle shutdown signals gracefully.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        signal_name = signal.Signals(signum).name
        logger.info(f"Received {signal_name} signal, initiating shutdown...")
        self._shutdown_requested = True
    
    def _process_flow(self, event: Dict[str, Any]) -> None:
        """
        Process a single flow event through the detection pipeline.
        
        Args:
            event: Suricata flow event dictionary
        """
        start_time = time.perf_counter()
        
        try:
            # Extract source IP for tracking
            src_ip = event.get('src_ip', 'unknown')
            dest_ip = event.get('dest_ip', 'unknown')
            src_port = event.get('src_port')
            dest_port = event.get('dest_port')
            proto = event.get('proto', 'unknown')
            
            # Extract and scale features
            features = self.extractor.extract_and_scale(event)
            
            if features is None:
                logger.debug("Failed to extract features from flow event")
                return
            
            # Reshape for prediction (model expects 2D array)
            features_2d = features.reshape(1, -1)
            
            # Get prediction probability
            # predict_proba returns [[prob_benign, prob_malicious]]
            proba = self.model.predict_proba(features_2d)[0]
            
            # Assuming binary classification: index 1 is malicious class
            malicious_score = proba[1] if len(proba) > 1 else proba[0]
            
            # Get class prediction
            prediction = self.model.predict(features_2d)[0]
            prediction_label = "MALICIOUS" if prediction == 1 else "BENIGN"
            
            # Determine action based on threshold
            action_taken = "NONE"
            
            if malicious_score >= self.config.model.confidence_threshold:
                # High confidence malicious traffic
                self.perf.record_prediction(is_malicious=True)
                
                logger.warning(
                    f"THREAT DETECTED: {src_ip} -> {dest_ip} | "
                    f"Score: {malicious_score:.4f} | "
                    f"Protocol: {proto}"
                )
                
                # Take response action
                if not self.response.is_whitelisted(src_ip):
                    block_success = self.response.block_ip(
                        ip=src_ip,
                        reason=f"ML detection score {malicious_score:.4f}",
                        ttl=self.config.response.default_block_ttl,
                        actor="system",
                        score=malicious_score
                    )
                    
                    if block_success:
                        action_taken = "BLOCKED"
                        
                        # Send alert if configured
                        if self.config.alerts.smtp_enabled:
                            smtp_config = {
                                'enabled': True,
                                'server': self.config.alerts.smtp_server,
                                'port': self.config.alerts.smtp_port,
                                'use_tls': self.config.alerts.smtp_use_tls,
                                'username': self.config.alerts.smtp_username,
                                'password': self.config.alerts.smtp_password,
                                'from': self.config.alerts.alert_from,
                                'to': self.config.alerts.alert_to
                            }
                            
                            if self.response.send_alert(
                                src_ip, malicious_score, event, smtp_config
                            ):
                                self.perf.record_alert()
                                action_taken = "BLOCKED_AND_ALERTED"
                else:
                    logger.info(
                        f"Whitelisted IP {src_ip} detected as threat "
                        f"(score={malicious_score:.4f}) but not blocked"
                    )
                    action_taken = "WHITELISTED"
            
            else:
                # Below threshold - benign or low-confidence
                self.perf.record_prediction(is_malicious=False)
                
                logger.debug(
                    f"Flow: {src_ip} -> {dest_ip} | "
                    f"Score: {malicious_score:.4f} | "
                    f"Prediction: {prediction_label}"
                )
            
            # Resolve process information for the connection
            process_info = self.process_resolver.get_process_for_connection(
                local_ip=src_ip,
                local_port=src_port,
                remote_ip=dest_ip,
                remote_port=dest_port,
                protocol=proto
            )
            
            process_name = process_info['process'] if process_info else None
            pid = process_info['pid'] if process_info else None
            
            # Log the scored flow for analysis
            self.response.log_flow_score(
                src_ip=src_ip,
                dest_ip=dest_ip,
                score=malicious_score,
                prediction=prediction_label,
                action_taken=action_taken,
                src_port=src_port,
                dest_port=dest_port,
                proto=proto,
                process_name=process_name,
                pid=pid
            )
            
        except Exception as e:
            logger.error(
                f"Error processing flow event: {e}",
                exc_info=True
            )
        
        finally:
            # Record performance metrics
            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000
            self.perf.record_flow(latency_ms)
    
    def run(self) -> None:
        """
        Start the main detection loop.
        
        This is a blocking call that runs until a shutdown signal is received.
        """
        if self._running:
            logger.warning("Decision engine is already running")
            return
        
        self._running = True
        logger.info("=" * 60)
        logger.info("AI-Powered Threat Detection & Response System")
        logger.info("Debre Berhan University - Department of IT")
        logger.info("=" * 60)
        logger.info(f"Model: {self.config.model.xgboost_path}")
        logger.info(f"Confidence Threshold: {self.config.model.confidence_threshold}")
        logger.info(f"Suricata EVE JSON: {self.config.suricata.eve_json_path}")
        logger.info(f"Whitelist: {len(self.config.response.whitelist)} IPs")
        logger.info("=" * 60)
        logger.info("Starting detection loop... (Press Ctrl+C to stop)")
        
        last_stats_time = time.time()
        stats_interval = 60  # Log stats every 60 seconds
        
        try:
            # Start watching Suricata events
            for event in self.watcher.watch(start_timeout=60.0):
                # Check for shutdown request
                if self._shutdown_requested:
                    logger.info("Shutdown requested, stopping detection loop")
                    break
                
                # Process the flow event
                self._process_flow(event)
                
                # Periodic stats logging
                if time.time() - last_stats_time >= stats_interval:
                    self.perf.log_stats()
                    last_stats_time = time.time()
        
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        
        except Exception as e:
            logger.error(f"Fatal error in detection loop: {e}", exc_info=True)
            raise
        
        finally:
            self._running = False
            self._shutdown()
    
    def _shutdown(self) -> None:
        """Perform clean shutdown of all components."""
        logger.info("Shutting down decision engine...")
        
        # Log final statistics
        logger.info("=" * 60)
        logger.info("FINAL STATISTICS")
        self.perf.log_stats()
        logger.info("=" * 60)
        
        # Cleanup components
        try:
            self.watcher.close()
        except Exception as e:
            logger.error(f"Error closing watcher: {e}")
        
        try:
            self.response.shutdown()
        except Exception as e:
            logger.error(f"Error shutting down response manager: {e}")
        
        logger.info("Decision engine shutdown complete")


def setup_logging(config: Config) -> None:
    """
    Setup logging configuration from config file.
    
    Args:
        config: System configuration
    """
    from logging.handlers import RotatingFileHandler
    
    # Create logs directory
    log_file = Path(config.logging.file)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, config.logging.level.upper()))
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=config.logging.max_bytes,
        backupCount=config.logging.backup_count
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)


def main():
    """
    Main entry point for the decision engine.
    
    Usage:
        python decision_engine.py [config_path]
    """
    print("AI-Powered Threat Detection & Response System")
    print("Debre Berhan University - Department of IT")
    print()
    
    # Get config path from command line or use default
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    
    try:
        # Load configuration
        print(f"Loading configuration from {config_path}...")
        config = load_config(config_path)
        
        # Setup logging
        setup_logging(config)
        logger.info("Configuration loaded successfully")
        
        # Check for administrator privileges
        if not ResponseManager._is_admin():
            logger.error(
                "This program requires Administrator privileges to modify "
                "Windows Firewall rules."
            )
            print("\nERROR: Administrator privileges required!")
            print("Please run this program as Administrator.")
            sys.exit(1)
        
        # Initialize and run decision engine
        engine = DecisionEngine(config)
        engine.run()
        
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\n\nShutdown requested by user")
        sys.exit(0)
    
    except FileNotFoundError as e:
        print(f"\nERROR: {e}")
        logger.error(f"File not found: {e}")
        sys.exit(1)
    
    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        logger.error(f"Fatal error: {e}", exc_info=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
