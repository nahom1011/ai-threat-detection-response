"""
Dashboard configuration for AI-Powered Threat Detection System.

Loads configuration from environment variables with secure defaults.
"""

import os
from pathlib import Path
from typing import Optional


class DashboardConfig:
    """Configuration for the Flask dashboard application."""
    
    # Flask configuration
    SECRET_KEY: str = os.getenv('DASHBOARD_SECRET_KEY', '')
    
    # Session configuration
    SESSION_COOKIE_SECURE: bool = False  # Set to True if using HTTPS
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = 'Lax'
    PERMANENT_SESSION_LIFETIME: int = 3600  # 1 hour
    
    # Database paths
    THREAT_DB_PATH: str = os.getenv(
        'THREAT_DB_PATH',
        str(Path(__file__).parent.parent / 'data' / 'threat_defense.db')
    )
    
    AUTH_DB_PATH: str = os.getenv(
        'DASHBOARD_AUTH_DB_PATH',
        str(Path(__file__).parent.parent / 'data' / 'dashboard_auth.db')
    )
    
    # Server configuration
    HOST: str = os.getenv('DASHBOARD_HOST', '127.0.0.1')
    PORT: int = int(os.getenv('DASHBOARD_PORT', '5000'))
    DEBUG: bool = os.getenv('DASHBOARD_DEBUG', 'False').lower() == 'true'
    
    # API configuration
    API_STATS_LIMIT: int = 1000  # Max flows to analyze for stats
    API_ALERTS_LIMIT: int = 50   # Max recent threats to return
    API_HISTORY_LIMIT: int = 100 # Max audit log entries to return
    
    # ML Model configuration (from backend)
    CONFIDENCE_THRESHOLD: float = 0.70  # Must match backend config.yaml
    
    @classmethod
    def validate(cls) -> None:
        """
        Validate configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if not cls.SECRET_KEY:
            raise ValueError(
                "DASHBOARD_SECRET_KEY environment variable must be set. "
                "Generate a secure random key:\n"
                "  python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        
        if len(cls.SECRET_KEY) < 32:
            raise ValueError(
                "DASHBOARD_SECRET_KEY must be at least 32 characters long"
            )
        
        # Validate database paths exist or can be created
        threat_db = Path(cls.THREAT_DB_PATH)
        if not threat_db.parent.exists():
            raise ValueError(
                f"Threat database directory does not exist: {threat_db.parent}"
            )
        
        auth_db = Path(cls.AUTH_DB_PATH)
        auth_db.parent.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def get_flask_config(cls) -> dict:
        """
        Get Flask-compatible configuration dictionary.
        
        Returns:
            Dictionary of Flask configuration values
        """
        return {
            'SECRET_KEY': cls.SECRET_KEY,
            'SESSION_COOKIE_SECURE': cls.SESSION_COOKIE_SECURE,
            'SESSION_COOKIE_HTTPONLY': cls.SESSION_COOKIE_HTTPONLY,
            'SESSION_COOKIE_SAMESITE': cls.SESSION_COOKIE_SAMESITE,
            'PERMANENT_SESSION_LIFETIME': cls.PERMANENT_SESSION_LIFETIME,
        }
