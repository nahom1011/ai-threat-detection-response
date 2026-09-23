"""Quick user creation without module imports."""
import sys
import getpass
import sqlite3
from pathlib import Path
from datetime import datetime
from werkzeug.security import generate_password_hash

def validate_password(password):
    """Validate password strength."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        return False, f"Password must contain at least one special character: {special_chars}"
    return True, "OK"

print("=" * 60)
print("AI-Powered Threat Detection Dashboard - Quick User Creation")
print("=" * 60)
print()

# Get username
username = input("Username: ").strip()
if not username:
    print("ERROR: Username is required")
    sys.exit(1)

# Get role
print()
print("Roles:")
print("  1. Administrator (can view and unblock IPs)")
print("  2. Security Analyst (can view only)")
print()
role_choice = input("Select role (1 or 2): ").strip()

if role_choice == '1':
    role = 'admin'
elif role_choice == '2':
    role = 'analyst'
else:
    print("ERROR: Invalid choice")
    sys.exit(1)

# Get password
print()
print("Password requirements:")
print("  • At least 12 characters")
print("  • At least one uppercase letter")
print("  • At least one lowercase letter")
print("  • At least one digit")
print("  • At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)")
print()

while True:
    password = getpass.getpass("Password: ")
    if not password:
        print("ERROR: Password is required")
        continue
    
    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        print("ERROR: Passwords do not match")
        continue
    
    valid, msg = validate_password(password)
    if not valid:
        print(f"ERROR: {msg}")
        continue
    
    break

# Hash password
password_hash = generate_password_hash(password, method='pbkdf2:sha256')

# Create database directory if needed
db_path = Path("data/dashboard_auth.db")
db_path.parent.mkdir(parents=True, exist_ok=True)

# Create database and user
try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create table if not exists
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
    
    # Insert user
    cursor.execute("""
        INSERT INTO users (username, password_hash, role, is_active, created_at)
        VALUES (?, ?, ?, 1, ?)
    """, (username, password_hash, role, datetime.utcnow().isoformat()))
    
    conn.commit()
    conn.close()
    
    role_name = "Administrator" if role == 'admin' else "Security Analyst"
    print()
    print("✓ User account created successfully!")
    print(f"  Username: {username}")
    print(f"  Role: {role_name}")
    print()
    print("You can now log in to the dashboard at:")
    print("  http://127.0.0.1:5000")
    
except sqlite3.IntegrityError:
    print()
    print(f"ERROR: Username '{username}' already exists")
    sys.exit(1)
except Exception as e:
    print()
    print(f"ERROR: {e}")
    sys.exit(1)
