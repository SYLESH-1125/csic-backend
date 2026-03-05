#!/usr/bin/env python3
"""Add AI parsing fields to template_registry table"""

from app.db.session import engine
from app.core.logging import logger
import sqlite3
from app.config import settings


def migrate_template_ai_fields():
    """Add AI parsing and learning fields to template_registry table."""
    db_path = settings.SQLITE_DB_PATH
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check existing columns
        cursor.execute("PRAGMA table_info(template_registry)")
        columns = [col[1] for col in cursor.fetchall()]
        
        new_columns = {
            'learned_patterns': 'TEXT',
            'pattern_hash': 'VARCHAR',
            'match_count': 'INTEGER DEFAULT 1',
            'last_seen': 'TIMESTAMP'
        }
        
        for col_name, col_type in new_columns.items():
            if col_name not in columns:
                logger.info(f"Adding column: {col_name}")
                cursor.execute(f"""
                    ALTER TABLE template_registry 
                    ADD COLUMN {col_name} {col_type}
                """)
            else:
                logger.info(f"Column {col_name} already exists")
        
        # Update existing records to have default values
        cursor.execute("""
            UPDATE template_registry 
            SET match_count = 1, last_seen = created_at 
            WHERE match_count IS NULL
        """)
        
        conn.commit()
        conn.close()
        
        logger.info("✓ Added AI parsing fields to template_registry table")
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise


if __name__ == "__main__":
    migrate_template_ai_fields()


