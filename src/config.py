"""
Configuration loader for AI-Powered Threat Detection & Response System.

Loads configuration from config.yaml and provides type-safe access to settings.
Environment variables override config file values for sensitive data.
"""

import os
import yaml
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class SuricataConfig:
    """Suricata-related configuration."""
    eve_json_path: str


@dataclass
class ModelConfig:
    """Machine learning model configuration."""
    xgboost_path: str
    scaler_path: str
    confidence_threshold: float


@dataclass
class ResponseConfig:
    """Response action configuration."""
    whitelist: List[str]
    default_block_ttl: int
    firewall_rule_prefix: str
    cleanup_interval: int


@dataclass
class AlertConfig:
    """Alert notification configuration."""
    smtp_enabled: bool
    smtp_server: str
    smtp_port: int
    smtp_use_tls: bool
    smtp_username: str
    smtp_password: str
    alert_from: str
    alert_to: List[str]


@dataclass
class DatabaseConfig:
    """Database configuration."""
    path: str


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str
    file: str
    max_bytes: int
    backup_count: int


@dataclass
class PerformanceConfig:
    """Performance monitoring configuration."""
    max_flow_latency_ms: int
    batch_size: int


class Config:
    """Main configuration class."""
    
    def __init__(self, config_path: str = "config.yaml"):
        """
        Load configuration from YAML file.
        
        Args:
            config_path: Path to configuration file
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If config file is malformed
        """
        self.config_path = Path(config_path)
        
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_path.absolute()}"
            )
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            try:
                self._raw_config: Dict[str, Any] = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise ValueError(f"Invalid YAML in config file: {e}")
        
        self._load_configs()
    
    def _load_configs(self) -> None:
        """Load all configuration sections."""
        # Suricata
        suricata_data = self._raw_config.get('suricata', {})
        self.suricata = SuricataConfig(
            eve_json_path=suricata_data.get('eve_json_path', 
                                           'C:\\Program Files\\Suricata\\log\\eve.json')
        )
        
        # Model
        model_data = self._raw_config.get('model', {})
        self.model = ModelConfig(
            xgboost_path=model_data.get('xgboost_path', 'models/xgboost.joblib'),
            scaler_path=model_data.get('scaler_path', 'models/scaler.joblib'),
            confidence_threshold=model_data.get('confidence_threshold', 0.85)
        )
        
        # Response
        response_data = self._raw_config.get('response', {})
        self.response = ResponseConfig(
            whitelist=response_data.get('whitelist', ['127.0.0.1', '::1']),
            default_block_ttl=response_data.get('default_block_ttl', 3600),
            firewall_rule_prefix=response_data.get('firewall_rule_prefix', 
                                                   'AIThreatDefense_Block_'),
            cleanup_interval=response_data.get('cleanup_interval', 300)
        )
        
        # Alerts - override credentials from environment
        alert_data = self._raw_config.get('alerts', {})
        self.alerts = AlertConfig(
            smtp_enabled=alert_data.get('smtp_enabled', False),
            smtp_server=alert_data.get('smtp_server', 'smtp.example.com'),
            smtp_port=alert_data.get('smtp_port', 587),
            smtp_use_tls=alert_data.get('smtp_use_tls', True),
            smtp_username=os.getenv('SMTP_USERNAME', 
                                   alert_data.get('smtp_username', '')),
            smtp_password=os.getenv('SMTP_PASSWORD', 
                                   alert_data.get('smtp_password', '')),
            alert_from=alert_data.get('alert_from', 'threat-defense@example.com'),
            alert_to=alert_data.get('alert_to', ['admin@example.com'])
        )
        
        # Database
        db_data = self._raw_config.get('database', {})
        self.database = DatabaseConfig(
            path=db_data.get('path', 'data/threat_defense.db')
        )
        
        # Logging
        log_data = self._raw_config.get('logging', {})
        self.logging = LoggingConfig(
            level=log_data.get('level', 'INFO'),
            file=log_data.get('file', 'logs/threat_defense.log'),
            max_bytes=log_data.get('max_bytes', 10485760),
            backup_count=log_data.get('backup_count', 5)
        )
        
        # Performance
        perf_data = self._raw_config.get('performance', {})
        self.performance = PerformanceConfig(
            max_flow_latency_ms=perf_data.get('max_flow_latency_ms', 100),
            batch_size=perf_data.get('batch_size', 1)
        )
    
    def validate(self) -> None:
        """
        Validate configuration values.
        
        Raises:
            ValueError: If any configuration value is invalid
        """
        # Validate threshold
        if not 0.0 <= self.model.confidence_threshold <= 1.0:
            raise ValueError(
                f"confidence_threshold must be between 0.0 and 1.0, "
                f"got {self.model.confidence_threshold}"
            )
        
        # Validate paths exist
        eve_path = Path(self.suricata.eve_json_path)
        if not eve_path.parent.exists():
            raise ValueError(
                f"Suricata log directory does not exist: {eve_path.parent}"
            )
        
        # Validate whitelist
        if not self.response.whitelist:
            raise ValueError("Response whitelist cannot be empty")
        
        # Validate SMTP if enabled
        if self.alerts.smtp_enabled:
            if not self.alerts.smtp_username or not self.alerts.smtp_password:
                raise ValueError(
                    "SMTP credentials required when alerts are enabled. "
                    "Set SMTP_USERNAME and SMTP_PASSWORD environment variables."
                )


# Global config instance
_config: Config = None


def load_config(config_path: str = "config.yaml") -> Config:
    """
    Load and return global configuration instance.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Loaded configuration object
    """
    global _config
    if _config is None:
        _config = Config(config_path)
        _config.validate()
    return _config


def get_config() -> Config:
    """
    Get the global configuration instance.
    
    Returns:
        Configuration object
        
    Raises:
        RuntimeError: If config hasn't been loaded yet
    """
    if _config is None:
        raise RuntimeError(
            "Configuration not loaded. Call load_config() first."
        )
    return _config
