"""
Authentication module for the dashboard.

Implements Flask-Login based authentication with role-based access control (RBAC).
Passwords are hashed using Werkzeug's security functions.
"""

import sqlite3
import logging
from pathlib import Path
from typing import Optional
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

from dashboard.config import DashboardConfig


logger = logging.getLogger(__name__)


# Role constants
ROLE_ADMIN = 'admin'
ROLE_ANALYST = 'analyst'

VALID_ROLES = {ROLE_ADMIN, ROLE_ANALYST}


class User(UserMixin):
    """
    User model for Flask-Login authentication.
    
    Represents a dashboard user with username, hashed password, and role.
    """
    
    def __init__(
        self,
        user_id: int,
        username: str,
        password_hash: str,
        role: str,
        is_active: bool = True
    ):
        """
        Initialize a User instance.
        
        Args:
            user_id: Unique user ID
            username: Username
            password_hash: Hashed password (never plaintext)
            role: User role ('admin' or 'analyst')
            is_active: Whether the user account is active
        """
        self.id = user_id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.active = is_active
    
    def get_id(self) -> str:
        """
        Get user ID as string (required by Flask-Login).
        
        Returns:
            User ID as string
        """
        return str(self.id)
    
    @property
    def is_active(self) -> bool:
        """
        Check if user is active (required by Flask-Login).
        
        Returns:
            True if user is active
        """
        return self.active
    
    @property
    def is_authenticated(self) -> bool:
        """
        Check if user is authenticated (required by Flask-Login).
        
        Returns:
            True (user objects are always authenticated)
        """
        return True
    
    @property
    def is_anonymous(self) -> bool:
        """
        Check if user is anonymous (required by Flask-Login).
        
        Returns:
            False (user objects are never anonymous)
        """
        return False
    
    def is_admin(self) -> bool:
        """
        Check if user has administrator role.
        
        Returns:
            True if user is an administrator
        """
        return self.role == ROLE_ADMIN
    
    def check_password(self, password: str) -> bool:
        """
        Verify a password against the stored hash.
        
        Args:
            password: Plaintext password to check
            
        Returns:
            True if password matches, False otherwise
        """
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self) -> str:
        """String representation of User."""
        return f"<User {self.username} ({self.role})>"


class AuthManager:
    """Manages user authentication and authorization."""
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the authentication manager.
        
        Args:
            db_path: Path to authentication database (uses config default if None)
        """
        self.db_path = Path(db_path or DashboardConfig.AUTH_DB_PATH)
        self._init_database()
        logger.info(f"AuthManager initialized with database: {self.db_path}")
    
    def _init_database(self) -> None:
        """
        Initialize the authentication database.
        
        Creates the users table if it doesn't exist.
        """
        try:
            # Ensure directory exists
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin', 'analyst')),
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_login TEXT
                )
            """)
            
            # Create index on username
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_username ON users(username)
            """)
            
            conn.commit()
            conn.close()
            
            logger.info("Authentication database initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize auth database: {e}")
            raise RuntimeError(f"Auth database initialization failed: {e}")
    
    def create_user(
        self,
        username: str,
        password: str,
        role: str
    ) -> bool:
        """
        Create a new user account.
        
        Args:
            username: Username (must be unique)
            password: Plaintext password (will be hashed)
            role: User role ('admin' or 'analyst')
            
        Returns:
            True if user created successfully, False if username exists
            
        Raises:
            ValueError: If role is invalid or password is weak
        """
        # Validate role
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role: {role}. Must be one of: {VALID_ROLES}")
        
        # Validate password strength
        self._validate_password_strength(password)
        
        # Hash password
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        
        try:
            from datetime import datetime
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO users (username, password_hash, role, is_active, created_at)
                VALUES (?, ?, ?, 1, ?)
            """, (username, password_hash, role, datetime.utcnow().isoformat()))
            
            conn.commit()
            conn.close()
            
            logger.info(f"User created: {username} ({role})")
            return True
            
        except sqlite3.IntegrityError:
            logger.warning(f"User creation failed: username '{username}' already exists")
            return False
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            raise
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User object if found, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, username, password_hash, role, is_active
                FROM users
                WHERE id = ?
            """, (user_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return User(
                    user_id=row[0],
                    username=row[1],
                    password_hash=row[2],
                    role=row[3],
                    is_active=bool(row[4])
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error fetching user by ID: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username.
        
        Args:
            username: Username
            
        Returns:
            User object if found, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, username, password_hash, role, is_active
                FROM users
                WHERE username = ?
            """, (username,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return User(
                    user_id=row[0],
                    username=row[1],
                    password_hash=row[2],
                    role=row[3],
                    is_active=bool(row[4])
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error fetching user by username: {e}")
            return None
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate a user with username and password.
        
        Args:
            username: Username
            password: Plaintext password
            
        Returns:
            User object if authentication successful, None otherwise
        """
        user = self.get_user_by_username(username)
        
        if user and user.is_active and user.check_password(password):
            # Update last login time
            self._update_last_login(user.id)
            logger.info(f"User authenticated: {username} ({user.role})")
            return user
        
        logger.warning(f"Authentication failed for username: {username}")
        return None
    
    def _update_last_login(self, user_id: int) -> None:
        """
        Update the last login timestamp for a user.
        
        Args:
            user_id: User ID
        """
        try:
            from datetime import datetime
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users
                SET last_login = ?
                WHERE id = ?
            """, (datetime.utcnow().isoformat(), user_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error updating last login: {e}")
    
    @staticmethod
    def _validate_password_strength(password: str) -> None:
        """
        Validate password meets strength requirements.
        
        Requirements:
        - At least 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        
        Args:
            password: Password to validate
            
        Raises:
            ValueError: If password doesn't meet requirements
        """
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters long")
        
        if not any(c.isupper() for c in password):
            raise ValueError("Password must contain at least one uppercase letter")
        
        if not any(c.islower() for c in password):
            raise ValueError("Password must contain at least one lowercase letter")
        
        if not any(c.isdigit() for c in password):
            raise ValueError("Password must contain at least one digit")
        
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            raise ValueError(
                f"Password must contain at least one special character: {special_chars}"
            )
