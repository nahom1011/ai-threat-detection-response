#!/usr/bin/env python3
"""
Database Migration: Add process_name and pid columns to flow_scores table.

Adds application context to network flows for better threat analysis.
"""

import sqlite3
import sys
from pathlib import Path

def migrate_database(db_path: str = "data/threat_defense.db"):
    """
    Add process_name and pid columns to flow_scores table.
    
    Args:
        db_path: Path to the database file
    """
    db_file = Path(db_path)
    
    if not db_file.exists():
        print(f"❌ Database not found: {db_path}")
        print("   The database will be created automatically when the backend runs.")
        return False
    
    print(f"📊 Migrating database: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(flow_scores)")
        columns = [row[1] for row in cursor.fetchall()]
        
        needs_migration = False
        
        if 'process_name' not in columns:
            print("   Adding process_name column...")
            cursor.execute("ALTER TABLE flow_scores ADD COLUMN process_name TEXT")
            needs_migration = True
        else:
            print("   ✓ process_name column already exists")
        
        if 'pid' not in columns:
            print("   Adding pid column...")
            cursor.execute("ALTER TABLE flow_scores ADD COLUMN pid TEXT")
            needs_migration = True
        else:
            print("   ✓ pid column already exists")
        
        if needs_migration:
            # Create index on process_name for performance
            print("   Creating index on process_name...")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_flow_process_name "
                "ON flow_scores(process_name)"
            )
            
            conn.commit()
            print("✅ Migration completed successfully!")
        else:
            print("✅ Database is already up-to-date!")
        
        # Show table schema
        print("\n📋 Current flow_scores schema:")
        cursor.execute("PRAGMA table_info(flow_scores)")
        for row in cursor.fetchall():
            col_id, col_name, col_type, not_null, default, pk = row
            print(f"   - {col_name} ({col_type})")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False


if __name__ == "__main__":
    db_path = sys.argv[1] if len(sys.argv) > 1 else "data/threat_defense.db"
    success = migrate_database(db_path)
    sys.exit(0 if success else 1)
