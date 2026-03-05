#!/usr/bin/env python3
"""Add template_word_category column to template_registry table"""

from app.db.session import engine
from app.core.logging import logger
import sqlite3
from app.config import settings


def migrate_add_template_category():
    """Add template_word_category column to template_registry table."""
    db_path = settings.SQLITE_DB_PATH
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if column exists
        cursor.execute("PRAGMA table_info(template_registry)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'template_word_category' in columns:
            logger.info("Column 'template_word_category' already exists")
            conn.close()
            return
        
        # Add column
        cursor.execute("""
            ALTER TABLE template_registry 
            ADD COLUMN template_word_category TEXT
        """)
        
        conn.commit()
        conn.close()
        
        logger.info("✓ Added 'template_word_category' column to template_registry table")
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise


if __name__ == "__main__":
    migrate_add_template_category()


