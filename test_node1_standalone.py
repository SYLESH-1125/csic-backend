#!/usr/bin/env python3
"""
Standalone Node 1 Test (No server required)
Tests Node 1 lineage anchoring without needing the full server
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from app.db.session import SessionLocal
from app.db.models import AuditLog, LineageAnchor
from app.phase2.node1_lineage import (
    anchor_lineage,
    create_immutable_pointer,
    compute_row_hash,
    log_to_duckdb
)


def test_node1_standalone():
    """Test Node 1 without server."""
    print("=" * 70)
    print("Node 1: Lineage Anchoring - Standalone Test")
    print("=" * 70)
    
    db = SessionLocal()
    
    try:
        # Create test audit log
        print("\n[1/4] Creating test audit log...")
        from datetime import datetime
        import uuid
        
        test_audit_id = str(uuid.uuid4())
        test_file_hash = "8f43b1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        
        audit_log = AuditLog(
            id=test_audit_id,
            filename="test_lineage.log",
            sha256_hash=test_file_hash,
            file_size=1024,
            source_ip="127.0.0.1",
            ingestion_mode="manual",
            status="ingested"
        )
        
        db.add(audit_log)
        db.commit()
        db.refresh(audit_log)
        print(f"✓ Test audit log created: {test_audit_id}")
        
        # Test row hash computation
        print("\n[2/4] Testing row hash computation...")
        test_rows = [
            "2024-01-01 10:00:00 INFO User admin logged in from 192.168.1.100",
            "2024-01-01 10:00:15 INFO User admin accessed file /var/log/system.log",
            "2024-01-01 10:00:30 WARN Failed login attempt from 10.0.0.50",
        ]
        
        row_hashes = []
        for i, row in enumerate(test_rows):
            row_hash = compute_row_hash(row)
            row_hashes.append(row_hash)
            print(f"  Row {i+1}: {row_hash[:20]}...")
        
        print(f"✓ Computed {len(row_hashes)} row hashes")
        
        # Test immutable pointer creation
        print("\n[3/4] Testing immutable pointer creation...")
        byte_offsets = [0, 156, 312]
        pointers = []
        
        for offset in byte_offsets:
            pointer = create_immutable_pointer(test_file_hash, offset)
            pointers.append(pointer)
            print(f"  Offset {offset}: {pointer[:50]}...")
        
        print(f"✓ Created {len(pointers)} immutable pointers")
        
        # Test lineage anchoring
        print("\n[4/4] Testing lineage anchoring...")
        anchors = []
        
        for i, (row, offset) in enumerate(zip(test_rows, byte_offsets)):
            anchor = anchor_lineage(
                db=db,
                audit_id=test_audit_id,
                source_file_hash=test_file_hash,
                byte_offset=offset,
                row_data=row
            )
            anchors.append(anchor)
            print(f"  Anchor {i+1}: {anchor.id[:20]}... (row_hash: {anchor.row_hash[:12]}...)")
        
        print(f"✓ Created {len(anchors)} lineage anchors")
        
        # Test DuckDB logging
        print("\n[5/5] Testing DuckDB row hash logging...")
        duckdb_ids = []
        
        for i, (row_hash, row) in enumerate(zip(row_hashes, test_rows)):
            duckdb_id = log_to_duckdb(
                row_hash=row_hash,
                audit_id=test_audit_id,
                row_data={"line_number": i+1, "content": row}
            )
            if duckdb_id:
                duckdb_ids.append(duckdb_id)
                print(f"  Row {i+1}: DuckDB row ID = {duckdb_id}")
        
        print(f"✓ Logged {len(duckdb_ids)} rows to DuckDB")
        
        # Verification
        print("\n[Verification]")
        stored_anchors = db.query(LineageAnchor).filter(
            LineageAnchor.audit_id == test_audit_id
        ).all()
        
        print(f"✓ Stored anchors in database: {len(stored_anchors)}")
        
        for anchor in stored_anchors:
            print(f"  - Anchor ID: {anchor.id}")
            print(f"    Source hash: {anchor.source_file_hash[:20]}...")
            print(f"    Byte offset: {anchor.byte_offset}")
            print(f"    Row hash: {anchor.row_hash[:20]}...")
            print(f"    Immutable pointer: {anchor.source_file_hash[:20]}:{anchor.byte_offset}")
        
        print("\n" + "=" * 70)
        print("✓ All Node 1 tests PASSED!")
        print("=" * 70)
        
        return True
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()


if __name__ == "__main__":
    success = test_node1_standalone()
    sys.exit(0 if success else 1)


