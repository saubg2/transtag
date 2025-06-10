#!/usr/bin/env python3
"""
Simple database migration to add is_standard_tag column to Rule table
"""
import sqlite3
import os

def migrate_database():
    db_path = os.path.join('instance', 'transactions.db')
    
    if not os.path.exists(db_path):
        print("Database not found, skipping migration")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if column already exists
        cursor.execute("PRAGMA table_info(rule)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'is_standard_tag' not in columns:
            print("Adding is_standard_tag column to rule table...")
            cursor.execute("ALTER TABLE rule ADD COLUMN is_standard_tag BOOLEAN NOT NULL DEFAULT 0")
            conn.commit()
            print("Migration completed successfully!")
        else:
            print("Column already exists, no migration needed")
    
    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
    
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database()