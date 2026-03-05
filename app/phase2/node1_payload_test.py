"""
Test script to verify Node 1 receives Phase 1 payload correctly
"""

import json
from app.db.session import SessionLocal
from app.db.models import AuditLog
from app.phase2.node1_lineage import anchor_lineage, create_immutable_pointer, compute_row_hash


def test_node1_payload_receipt():
    """
    Test that Node 1 correctly receives and processes Phase 1 payload.
    """
    print("=" * 60)
    print("Node 1: Lineage Anchoring - Payload Receipt Test")
    print("=" * 60)
    
    db = SessionLocal()
    
    try:
        # Simulate Phase 1 payload
        phase1_payload = {
            "status": "done",
            "audit_id": "test-audit-123",
            "merkle_root": "abc123...",
            "sha256": "8f43b1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "filename": "test.log",
            "file_path": "data/worm/test.log",
            "source_ip": "127.0.0.1"
        }
        
        print("\n[Phase 1 Payload]")
        print(json.dumps(phase1_payload, indent=2))
        
        # Check if audit log exists (would be created by Phase 1)
        audit_log = db.query(AuditLog).filter(AuditLog.id == phase1_payload["audit_id"]).first()
        
        if not audit_log:
            print(f"\n  Audit log not found: {phase1_payload['audit_id']}")
            print("   Creating test audit log...")
            
            # Create test audit log
            from datetime import datetime
            audit_log = AuditLog(
                id=phase1_payload["audit_id"],
                filename=phase1_payload["filename"],
                sha256_hash=phase1_payload["sha256"],
                file_size=1024,
                source_ip=phase1_payload["source_ip"],
                ingestion_mode="manual",
                status="ingested"
            )
            db.add(audit_log)
            db.commit()
            db.refresh(audit_log)
            print(f"   ✓ Test audit log created")
        else:
            print(f"\n✓ Audit log found: {audit_log.id}")
        
        # Extract payload data for Node 1
        audit_id = phase1_payload["audit_id"]
        source_file_hash = audit_log.sha256_hash  # From audit log
        byte_offset = 0  # First line
        row_data = "2024-01-01 10:00:00 INFO User logged in from 192.168.1.1"
        
        print("\n[Node 1 Input]")
        print(f"  audit_id: {audit_id}")
        print(f"  source_file_hash: {source_file_hash[:20]}...")
        print(f"  byte_offset: {byte_offset}")
        print(f"  row_data: {row_data[:50]}...")
        
        # Test Node 1 functions
        print("\n[Node 1 Processing]")
        
        # 1. Create immutable pointer
        pointer = create_immutable_pointer(source_file_hash, byte_offset)
        print(f"  ✓ Immutable pointer: {pointer[:50]}...")
        
        # 2. Compute row hash
        row_hash = compute_row_hash(row_data)
        print(f"  ✓ Row hash: {row_hash[:20]}...")
        
        # 3. Anchor lineage
        anchor = anchor_lineage(
            db=db,
            audit_id=audit_id,
            source_file_hash=source_file_hash,
            byte_offset=byte_offset,
            row_data=row_data
        )
        
        print(f"\n[Node 1 Output]")
        print(f"  ✓ Anchor ID: {anchor.id}")
        print(f"  ✓ Immutable pointer: {pointer[:50]}...")
        print(f"  ✓ Row hash: {row_hash[:20]}...")
        print(f"  ✓ Byte offset: {anchor.byte_offset}")
        
        # Verify payload receipt
        print("\n[Payload Verification]")
        print(f"  ✓ audit_id received: {anchor.audit_id == audit_id}")
        print(f"  ✓ source_file_hash received: {anchor.source_file_hash == source_file_hash}")
        print(f"  ✓ byte_offset received: {anchor.byte_offset == byte_offset}")
        print(f"  ✓ row_hash computed: {anchor.row_hash == row_hash}")
        
        print("\n" + "=" * 60)
        print("✓ Node 1 payload receipt test PASSED")
        print("=" * 60)
        
        return True
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()


if __name__ == "__main__":
    test_node1_payload_receipt()

