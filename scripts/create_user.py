"""
User creation script for AI-Powered Threat Detection Dashboard.

Creates dashboard user accounts with secure password hashing.
"""

import sys
import getpass
from pathlib import Path

# Add project root to path so we can import dashboard module
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from dashboard.auth import AuthManager, ROLE_ADMIN, ROLE_ANALYST


def print_banner():
    """Print script banner."""
    print("=" * 60)
    print("AI-Powered Threat Detection Dashboard - User Creation")
    print("Debre Berhan University - Department of IT")
    print("=" * 60)
    print()


def get_user_input():
    """
    Get user input for account creation.
    
    Returns:
        Tuple of (username, password, role)
    """
    print("Create a new dashboard user account")
    print()
    
    # Get username
    while True:
        username = input("Username: ").strip()
        if username:
            if len(username) < 3:
                print("❌ Username must be at least 3 characters long")
                continue
            if len(username) > 50:
                print("❌ Username must be at most 50 characters long")
                continue
            break
        print("❌ Username is required")
    
    # Get role
    print()
    print("Roles:")
    print("  1. Administrator (can view and unblock IPs)")
    print("  2. Security Analyst (can view only)")
    print()
    
    while True:
        role_choice = input("Select role (1 or 2): ").strip()
        if role_choice == '1':
            role = ROLE_ADMIN
            break
        elif role_choice == '2':
            role = ROLE_ANALYST
            break
        print("❌ Invalid choice. Enter 1 or 2")
    
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
            print("❌ Password is required")
            continue
        
        password_confirm = getpass.getpass("Confirm password: ")
        
        if password != password_confirm:
            print("❌ Passwords do not match")
            continue
        
        break
    
    return username, password, role


def create_user_account(username, password, role):
    """
    Create user account using AuthManager.
    
    Args:
        username: Username
        password: Plaintext password (will be hashed)
        role: User role
        
    Returns:
        True if successful, False otherwise
    """
    try:
        auth_manager = AuthManager()
        
        # Create user
        success = auth_manager.create_user(username, password, role)
        
        if success:
            return True
        else:
            print()
            print("❌ Failed to create user")
            print(f"   Username '{username}' may already exist")
            return False
            
    except ValueError as e:
        print()
        print(f"❌ Validation error: {e}")
        return False
    except Exception as e:
        print()
        print(f"❌ Error creating user: {e}")
        return False


def main():
    """Main entry point."""
    print_banner()
    
    try:
        # Get user input
        username, password, role = get_user_input()
        
        print()
        print("Creating user account...")
        
        # Create user
        if create_user_account(username, password, role):
            role_name = "Administrator" if role == ROLE_ADMIN else "Security Analyst"
            print()
            print("✓ User account created successfully!")
            print(f"  Username: {username}")
            print(f"  Role: {role_name}")
            print()
            print("The user can now log in to the dashboard at:")
            print("  http://127.0.0.1:5000")
            return 0
        else:
            return 1
            
    except KeyboardInterrupt:
        print()
        print()
        print("User creation cancelled")
        return 1
    except Exception as e:
        print()
        print(f"❌ Unexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
