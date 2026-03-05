#!/usr/bin/env python3
"""
Test script for Node 6: Human-in-the-Loop Staging
Tests staging entry creation, preview, confirmation, rejection, and commit
"""

import sys
import os
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.phase2.node6_staging import (
    create_staging_entry,
    get_staging_preview,
    confirm_staging,
    reject_staging,
    commit_staging,
    query_staging,
    get_staging_statistics
)
from app.db.session import SessionLocal
from app.db.models import AuditLog


def test_staging_creation():
    """Test staging entry creation"""
    print("\n[1/6] Testing Staging Entry Creation")
    print("-" * 70)
    
    db = SessionLocal()
    try:
        # Create a test audit log first
        from app.db.models import AuditLog
        test_audit = AuditLog(
            filename="test.log",
            sha256_hash="test_hash_123",
            file_size=100,
            source_ip="192.168.1.1"
        )
        db.add(test_audit)
        db.commit()
        db.refresh(test_audit)
        
        # Create staging entry
        row_data = {
            "line_number": 1,
            "original": "2024-01-15T10:30:00Z INFO User logged in",
            "decoded": "2024-01-15T10:30:00Z INFO User logged in",
            "template": "<timestamp> <level> <message>",
            "variables": {"timestamp": "2024-01-15T10:30:00Z", "level": "INFO", "message": "User logged in"},
            "ner_tags": {"ip_addresses": [], "emails": []},
            "timestamp": datetime.utcnow()
        }
        
        staging = create_staging_entry(
            db=db,
            audit_id=test_audit.id,
            row_data=row_data,
            decoded_payload={"decoded": row_data["decoded"]},
            extracted_variables=row_data["variables"],
            ner_tags=row_data["ner_tags"],
            normalized_timestamp=row_data["timestamp"]
        )
        
        print(f"  ✓ Staging entry created: {staging.id}")
        print(f"    Status: {staging.status}")
        print(f"    Row hash: {staging.row_hash[:16]}...")
        print(f"    Has template: {staging.template_id is not None}")
        print(f"    Has NER tags: {staging.ner_tags is not None}")
        print(f"    Has timestamp: {staging.normalized_timestamp is not None}")
        
        return staging.id, test_audit.id
        
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        import traceback
        traceback.print_exc()
        return None, None
    finally:
        db.close()


def test_staging_preview(staging_id: str):
    """Test staging preview"""
    print("\n[2/6] Testing Staging Preview")
    print("-" * 70)
    
    if not staging_id:
        print("  ⚠ Skipping: No staging ID")
        return
    
    db = SessionLocal()
    try:
        preview = get_staging_preview(db, staging_id, include_metadata=True)
        
        print(f"  ✓ Preview retrieved for: {staging_id}")
        print(f"    Status: {preview['status']}")
        print(f"    Has decoded payload: {preview['decoded_payload'] is not None}")
        print(f"    Has extracted variables: {preview['extracted_variables'] is not None}")
        print(f"    Has NER tags: {preview['ner_tags'] is not None}")
        print(f"    Has timestamp: {preview['normalized_timestamp'] is not None}")
        
        if 'processing_stats' in preview:
            stats = preview['processing_stats']
            print(f"    Processing stats:")
            print(f"      Variable count: {stats.get('variable_count', 0)}")
            print(f"      NER tag count: {stats.get('ner_tag_count', 0)}")
        
        if 'lineage' in preview:
            print(f"    Lineage: {preview['lineage'] is not None}")
        
        if 'template' in preview:
            print(f"    Template: {preview['template'] is not None}")
        
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()


def test_confirm_staging(staging_id: str):
    """Test staging confirmation"""
    print("\n[3/6] Testing Staging Confirmation")
    print("-" * 70)
    
    if not staging_id:
        print("  ⚠ Skipping: No staging ID")
        return
    
    db = SessionLocal()
    try:
        result = confirm_staging(
            db=db,
            staging_id=staging_id,
            human_overrides={"verified": True, "reviewer": "test_user"}
        )
        
        print(f"  ✓ Staging confirmed: {staging_id}")
        print(f"    Status: {result['status']}")
        print(f"    Has overrides: {result['has_overrides']}")
        
        # Verify status changed
        from app.db.models import StagingArea
        staging = db.query(StagingArea).filter(StagingArea.id == staging_id).first()
        print(f"    Current status: {staging.status}")
        
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()


def test_reject_staging(audit_id: str):
    """Test staging rejection"""
    print("\n[4/6] Testing Staging Rejection")
    print("-" * 70)
    
    if not audit_id:
        print("  ⚠ Skipping: No audit ID")
        return
    
    db = SessionLocal()
    try:
        # Create another staging entry for rejection test
        from app.db.models import StagingArea, AuditLog
        test_audit = db.query(AuditLog).filter(AuditLog.id == audit_id).first()
        
        row_data = {
            "line_number": 2,
            "original": "Invalid log entry",
            "decoded": None,
            "template": None,
            "variables": {},
            "ner_tags": {},
            "timestamp": None
        }
        
        staging = create_staging_entry(
            db=db,
            audit_id=test_audit.id,
            row_data=row_data
        )
        
        # Reject it
        result = reject_staging(
            db=db,
            staging_id=staging.id,
            reason="Invalid format, cannot parse"
        )
        
        print(f"  ✓ Staging rejected: {staging.id}")
        print(f"    Status: {result['status']}")
        print(f"    Reason: {result['reason']}")
        
        # Verify status changed
        staging = db.query(StagingArea).filter(StagingArea.id == staging.id).first()
        print(f"    Current status: {staging.status}")
        
        return staging.id
        
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        db.close()


def test_query_staging(audit_id: str):
    """Test staging query"""
    print("\n[5/6] Testing Staging Query")
    print("-" * 70)
    
    if not audit_id:
        print("  ⚠ Skipping: No audit ID")
        return
    
    db = SessionLocal()
    try:
        # Query by audit_id
        result = query_staging(
            db=db,
            audit_id=audit_id,
            limit=10
        )
        
        print(f"  ✓ Query executed")
        print(f"    Total: {result['total']}")
        print(f"    Count: {result['count']}")
        print(f"    Entries: {len(result['entries'])}")
        
        # Query by status
        result_pending = query_staging(
            db=db,
            audit_id=audit_id,
            status="pending",
            limit=10
        )
        print(f"    Pending entries: {result_pending['count']}")
        
        # Query by features
        result_with_template = query_staging(
            db=db,
            audit_id=audit_id,
            has_template=True,
            limit=10
        )
        print(f"    Entries with template: {result_with_template['count']}")
        
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()


def test_statistics(audit_id: str):
    """Test staging statistics"""
    print("\n[6/6] Testing Staging Statistics")
    print("-" * 70)
    
    if not audit_id:
        print("  ⚠ Skipping: No audit ID")
        return
    
    db = SessionLocal()
    try:
        stats = get_staging_statistics(db=db, audit_id=audit_id)
        
        print(f"  ✓ Statistics retrieved")
        print(f"    Total: {stats['total']}")
        print(f"    Status breakdown:")
        for status, count in stats['status_breakdown'].items():
            print(f"      {status}: {count}")
        
        print(f"    Feature presence:")
        for feature, count in stats['feature_presence'].items():
            percentage = stats['percentages'].get(feature.replace('has_', 'with_'), 0)
            print(f"      {feature}: {count} ({percentage:.1f}%)")
        
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()


def main():
    """Run all tests"""
    print("=" * 70)
    print("Node 6: Human-in-the-Loop Staging - Test Suite")
    print("=" * 70)
    
    try:
        # Test 1: Create staging entry
        staging_id, audit_id = test_staging_creation()
        
        if staging_id:
            # Test 2: Preview
            test_staging_preview(staging_id)
            
            # Test 3: Confirm
            test_confirm_staging(staging_id)
        
        if audit_id:
            # Test 4: Reject
            rejected_id = test_reject_staging(audit_id)
            
            # Test 5: Query
            test_query_staging(audit_id)
            
            # Test 6: Statistics
            test_statistics(audit_id)
        
        print("\n" + "=" * 70)
        print("All tests completed!")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n✗ Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()


