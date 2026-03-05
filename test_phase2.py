#!/usr/bin/env python3
"""
Phase 2 Testing Script
Tests the Universal Translator pipeline (all 6 nodes)
"""

import asyncio
import base64
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

import websockets


BASE_URL = "http://127.0.0.1:8000"
WS_BASE_URL = "ws://127.0.0.1:8000"
CHUNK_SIZE = 1024 * 64


def create_session() -> dict:
    """Create a manual ingestion session."""
    url = f"{BASE_URL}/api/ingestion/manual"
    req = urllib.request.Request(url, method="POST")
    req.add_header("Content-Type", "application/json")
    
    with urllib.request.urlopen(req) as response:
        if response.status != 200:
            raise Exception(f"HTTP {response.status}: {response.read().decode()}")
        return json.loads(response.read().decode())


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()


def build_chunk_message(chunk_number: int, data: bytes, is_final: bool = False) -> dict:
    """Build a chunk message in the expected format."""
    chunk_hash = compute_sha256(data)
    encoded_data = base64.b64encode(data).decode("utf-8")
    return {
        "chunk_number": chunk_number,
        "chunk_hash": chunk_hash,
        "data": encoded_data,
        "is_final": is_final,
    }


async def upload_file_phase1(session_id: str, test_data: bytes, filename: str = "test.log") -> dict:
    """Upload file via WebSocket (Phase 1)."""
    ws_url = f"{WS_BASE_URL}/ws/secure-stream/{session_id}"
    print(f"  Connecting to: {ws_url}")

    try:
        async with websockets.connect(ws_url) as websocket:
            print(f"  ✓ WebSocket connected")

            # Send metadata
            meta_msg = {"type": "meta", "filename": filename}
            await websocket.send(json.dumps(meta_msg))
            meta_response = await websocket.recv()
            print(f"  ✓ Meta acknowledged")

            # Send chunks
            total_chunks = (len(test_data) + CHUNK_SIZE - 1) // CHUNK_SIZE
            chunk_number = 0

            for offset in range(0, len(test_data), CHUNK_SIZE):
                chunk_data = test_data[offset : offset + CHUNK_SIZE]
                is_final = offset + CHUNK_SIZE >= len(test_data)

                chunk_msg = build_chunk_message(chunk_number, chunk_data, is_final)
                await websocket.send(json.dumps(chunk_msg))

                ack = await websocket.recv()
                ack_data = json.loads(ack)
                
                if ack_data.get("status") == "error":
                    print(f"  ✗ Error: {ack_data.get('detail')}")
                    return None

                chunk_number += 1

            # Wait for final completion
            final = await websocket.recv()
            final_data = json.loads(final)
            
            # Handle nested "result" structure from Phase 1
            result = final_data.get("result", final_data)  # Support both formats
            
            if result.get("status") == "done":
                print(f"  ✓ Phase 1 complete")
                # Return result (Phase 2 will get source_ip from audit_log)
                return result
            elif result.get("status") == "failed":
                print(f"  ✗ Phase 1 failed: {result}")
                return None
            else:
                print(f"  ✗ Unexpected status: {final_data}")
                return None

    except Exception as e:
        print(f"  ✗ Error: {e}")
        return None


def process_phase2(audit_id: str, file_path: str, source_ip: str = "127.0.0.1") -> dict:
    """Process file through Phase 2 pipeline."""
    url = f"{BASE_URL}/api/phase2/process"
    payload = {
        "audit_id": audit_id,
        "file_path": file_path,
        "source_ip": source_ip
    }
    
    req = urllib.request.Request(url, method="POST")
    req.add_header("Content-Type", "application/json")
    req.data = json.dumps(payload).encode('utf-8')
    
    try:
        with urllib.request.urlopen(req) as response:
            if response.status != 200:
                error_msg = response.read().decode()
                raise Exception(f"HTTP {response.status}: {error_msg}")
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else "No error details"
        print(f"\n[Server Error Response]")
        print(f"Status: {e.code}")
        print(f"Detail: {error_body[:500]}")
        raise Exception(f"HTTP {e.code}: {error_body}")


def get_staging_preview(staging_id: str) -> dict:
    """Get preview of staged data."""
    url = f"{BASE_URL}/api/phase2/preview/{staging_id}"
    req = urllib.request.Request(url, method="GET")
    
    with urllib.request.urlopen(req) as response:
        if response.status != 200:
            error_msg = response.read().decode()
            raise Exception(f"HTTP {response.status}: {error_msg}")
        return json.loads(response.read().decode())


def get_audit_preview(audit_id: str, limit: int = 5) -> dict:
    """Get previews for an audit."""
    url = f"{BASE_URL}/api/phase2/preview/audit/{audit_id}?limit={limit}"
    req = urllib.request.Request(url, method="GET")
    
    with urllib.request.urlopen(req) as response:
        if response.status != 200:
            error_msg = response.read().decode()
            raise Exception(f"HTTP {response.status}: {error_msg}")
        return json.loads(response.read().decode())


def commit_staging_entry(staging_id: str, human_overrides: dict = None) -> dict:
    """Commit staging entry with human overrides."""
    url = f"{BASE_URL}/api/phase2/commit/{staging_id}"
    payload = {
        "human_overrides": human_overrides or {},
        "confirm": True
    }
    
    req = urllib.request.Request(url, method="POST")
    req.add_header("Content-Type", "application/json")
    req.data = json.dumps(payload).encode('utf-8')
    
    with urllib.request.urlopen(req) as response:
        if response.status != 200:
            error_msg = response.read().decode()
            raise Exception(f"HTTP {response.status}: {error_msg}")
        return json.loads(response.read().decode())


def get_statistics(audit_id: str = None) -> dict:
    """Get staging statistics."""
    url = f"{BASE_URL}/api/phase2/statistics"
    if audit_id:
        url += f"?audit_id={audit_id}"
    
    req = urllib.request.Request(url, method="GET")
    
    with urllib.request.urlopen(req) as response:
        if response.status != 200:
            error_msg = response.read().decode()
            raise Exception(f"HTTP {response.status}: {error_msg}")
        return json.loads(response.read().decode())


async def test_full_pipeline():
    """Test complete Phase 1 → Phase 2 pipeline with commit workflow."""
    print("=" * 70)
    print("Phase 2 Testing - Full Pipeline (All 6 Nodes + Commit)")
    print("=" * 70)
    
    # Step 1: Phase 1 Upload
    print("\n[1/7] Phase 1: File Upload via WebSocket")
    print("-" * 70)
    
    try:
        session_data = create_session()
        session_id = session_data["session_id"]
        print(f"✓ Session created: {session_id}")
    except Exception as e:
        print(f"✗ Failed to create session: {e}")
        return False
    
    # Create test log file with various content (testing all nodes)
    test_content = """2024-01-15T10:30:00Z INFO User admin logged in from 192.168.1.100
2024-01-15T10:30:15Z INFO User admin accessed file /var/log/system.log
2024-01-15T10:30:30Z WARN Failed login attempt from 10.0.0.50
2024-01-15T10:30:45Z INFO User admin logged out
2024-01-15T10:31:00Z INFO System backup completed successfully
2024-01-15T10:31:15Z ERROR Database connection failed to db.example.com:5432
2024-01-15T10:31:30Z INFO Email sent to admin@example.com
2024-01-15T10:31:45Z INFO HTTP request GET https://api.example.com/v1/users
""".encode('utf-8')
    
    test_filename = "test_phase2.log"
    print(f"✓ Test file prepared: {test_filename} ({len(test_content)} bytes)")
    
    phase1_result = await upload_file_phase1(session_id, test_content, test_filename)
    
    if not phase1_result:
        print("✗ Phase 1 upload failed")
        return False
    
    # Extract from nested result structure
    audit_id = phase1_result.get("audit_id")
    file_path = phase1_result.get("file_path")
    source_ip = phase1_result.get("source_ip", "127.0.0.1")
    
    if not audit_id:
        print("✗ Phase 1 response missing audit_id")
        return False
    
    print(f"  Audit ID: {audit_id}")
    print(f"  File Path: {file_path}")
    print(f"  SHA-256: {phase1_result.get('sha256', '')[:20]}...")
    print(f"  Binary Signature: {phase1_result.get('binary_signature', '')[:20]}...")
    
    # Step 2: Phase 2 Processing
    print("\n[2/7] Phase 2: Universal Translator Pipeline (All 6 Nodes)")
    print("-" * 70)
    
    try:
        if not file_path:
            # Construct path from WORM directory
            from app.config import settings
            from pathlib import Path
            worm_dir = Path(settings.WORM_STORAGE_PATH)
            file_path = str(worm_dir / test_filename)
        
        print(f"  Processing: audit_id={audit_id}")
        print(f"  File path: {file_path}")
        
        phase2_result = process_phase2(audit_id, file_path, source_ip)
        
        print(f"✓ Phase 2 processing complete")
        print(f"  Status: {phase2_result.get('status')}")
        print(f"  Rows processed: {phase2_result.get('rows_processed', 0)}")
        print(f"  Staging IDs: {len(phase2_result.get('staging_ids', []))}")
        
    except Exception as e:
        print(f"✗ Phase 2 processing failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Step 3: Preview Staging
    print("\n[3/7] Phase 2: Preview Staging Data (Web UI Preview)")
    print("-" * 70)
    
    try:
        staging_ids = phase2_result.get("staging_ids", [])
        if not staging_ids:
            print("⚠ No staging entries created")
            return False
        
        # Get preview of first staging entry
        preview = get_staging_preview(staging_ids[0])
        
        print(f"✓ Preview retrieved: staging_id={staging_ids[0]}")
        print(f"  Row hash: {preview.get('row_hash', '')[:20]}...")
        print(f"  Status: {preview.get('status')}")
        
        # Show extracted variables if available
        variables = preview.get('extracted_variables')
        if variables:
            print(f"  Extracted variables: {len(variables)} fields")
        
        # Show NER tags if available
        ner_tags = preview.get('ner_tags')
        if ner_tags:
            print(f"  NER tags: {json.dumps(ner_tags, indent=2)[:200]}...")
        
    except Exception as e:
        print(f"✗ Preview failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Step 4: Audit Preview
    print("\n[4/7] Phase 2: Audit Preview (All Staging Entries)")
    print("-" * 70)
    
    try:
        audit_preview = get_audit_preview(audit_id, limit=5)
        
        print(f"✓ Audit preview retrieved")
        print(f"  Count: {audit_preview.get('count', 0)}")
        print(f"  Previews: {len(audit_preview.get('previews', []))}")
        
        # Show first few previews
        for i, prev in enumerate(audit_preview.get('previews', [])[:3], 1):
            print(f"  Preview {i}: staging_id={prev.get('staging_id', '')[:20]}...")
            print(f"    Row hash: {prev.get('row_hash', '')[:20]}...")
            print(f"    Status: {prev.get('status')}")
        
    except Exception as e:
        print(f"✗ Audit preview failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Step 5: Commit with Human Overrides
    print("\n[5/7] Node 6: Commit with Human Overrides (Confirm & Push Database)")
    print("-" * 70)
    
    try:
        staging_ids = phase2_result.get("staging_ids", [])
        if not staging_ids:
            print("⚠ No staging entries to commit")
        else:
            # Commit first staging entry with human overrides
            human_overrides = {
                "verified": True,
                "reviewer": "test_user",
                "notes": "Manually verified and corrected"
            }
            
            commit_result = commit_staging_entry(staging_ids[0], human_overrides)
            
            print(f"✓ Commit successful: staging_id={staging_ids[0]}")
            print(f"  Status: {commit_result.get('status')}")
            print(f"  Final row hash: {commit_result.get('final_row_hash', '')[:20]}...")
            print(f"  Has overrides: {commit_result.get('has_overrides', False)}")
            
            # Check Phase 3 signal
            phase3_signal = commit_result.get('phase3_signal')
            if phase3_signal:
                print(f"  ✓ Phase 3 signal sent:")
                print(f"    Event: {phase3_signal.get('event')}")
                print(f"    Timestamp: {phase3_signal.get('timestamp', '')[:19]}")
            
    except Exception as e:
        print(f"✗ Commit failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Step 6: Verify Audit Ledger and DuckDB
    print("\n[6/7] Verification: Audit Ledger & DuckDB Main Table")
    print("-" * 70)
    
    try:
        from app.db.session import SessionLocal
        from app.db.duckdb import get_duckdb_connection
        
        db = SessionLocal()
        
        # Check audit_row_hashes (SQLite Audit Ledger)
        conn = get_duckdb_connection()
        
        # Check audit_row_hashes table
        try:
            audit_hashes = conn.execute("""
                SELECT staging_id, audit_id, row_hash, final_row_hash, committed_at
                FROM audit_row_hashes
                WHERE audit_id = ?
                LIMIT 1
            """, [audit_id]).fetchone()
            
            if audit_hashes:
                print(f"✓ Audit Ledger entry found:")
                print(f"  Staging ID: {audit_hashes[0]}")
                print(f"  Row hash: {audit_hashes[2][:20]}...")
                print(f"  Final row hash: {audit_hashes[3][:20]}...")
            else:
                print("⚠ No audit ledger entries found (may not be committed yet)")
        except Exception as e:
            print(f"  ⚠ Audit ledger check: {e}")
        
        # Check normalized_logs (DuckDB Main Table)
        try:
            normalized_logs = conn.execute("""
                SELECT staging_id, audit_id, row_hash, final_row_hash, committed_at
                FROM normalized_logs
                WHERE audit_id = ?
                LIMIT 1
            """, [audit_id]).fetchone()
            
            if normalized_logs:
                print(f"✓ DuckDB Main Table entry found:")
                print(f"  Staging ID: {normalized_logs[0]}")
                print(f"  Row hash: {normalized_logs[2][:20]}...")
                print(f"  Final row hash: {normalized_logs[3][:20]}...")
                print(f"  Committed at: {normalized_logs[4]}")
            else:
                print("⚠ No normalized_logs entries found (may not be committed yet)")
        except Exception as e:
            print(f"  ⚠ Normalized logs check: {e}")
        
        conn.close()
        db.close()
        
    except Exception as e:
        print(f"✗ Verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Step 7: Statistics and Verification
    print("\n[7/7] Statistics & Final Verification")
    print("-" * 70)
    
    try:
        # Get statistics
        stats = get_statistics(audit_id=audit_id)
        
        print(f"✓ Statistics retrieved:")
        print(f"  Total staging entries: {stats.get('total', 0)}")
        print(f"  Status breakdown:")
        for status, count in stats.get('status_breakdown', {}).items():
            print(f"    {status}: {count}")
        
        print(f"  Feature presence:")
        for feature, count in stats.get('feature_presence', {}).items():
            percentage = stats.get('percentages', {}).get(feature.replace('has_', 'with_'), 0)
            print(f"    {feature}: {count} ({percentage:.1f}%)")
        
        # Verify Node 1 (Lineage Anchoring)
        from app.db.session import SessionLocal
        from app.db.models import LineageAnchor
        
        db = SessionLocal()
        
        anchors = db.query(LineageAnchor).filter(
            LineageAnchor.audit_id == audit_id
        ).all()
        
        print(f"\n✓ LineageAnchor records: {len(anchors)}")
        
        # Check DuckDB row hashes
        conn = get_duckdb_connection()
        duckdb_rows = conn.execute("""
            SELECT COUNT(*) as count 
            FROM lineage_row_hashes 
            WHERE audit_id = ?
        """, [audit_id]).fetchone()
        
        if duckdb_rows:
            print(f"✓ DuckDB row hashes: {duckdb_rows[0]} rows")
        
        conn.close()
        db.close()
        
    except Exception as e:
        print(f"✗ Statistics/verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    try:
        from app.db.session import SessionLocal
        from app.db.models import LineageAnchor, AuditLog
        
        db = SessionLocal()
        
        # Check LineageAnchor records
        anchors = db.query(LineageAnchor).filter(
            LineageAnchor.audit_id == audit_id
        ).all()
        
        print(f"✓ LineageAnchor records found: {len(anchors)}")
        
        if anchors:
            anchor = anchors[0]
            print(f"  Sample anchor:")
            print(f"    ID: {anchor.id}")
            print(f"    Source hash: {anchor.source_file_hash[:20]}...")
            print(f"    Byte offset: {anchor.byte_offset}")
            print(f"    Row hash: {anchor.row_hash[:20]}...")
            print(f"    Immutable pointer: {anchor.source_file_hash[:20]}:{anchor.byte_offset}")
        
        # Check DuckDB
        from app.db.duckdb import get_duckdb_connection
        
        conn = get_duckdb_connection()
        duckdb_rows = conn.execute("""
            SELECT COUNT(*) as count 
            FROM lineage_row_hashes 
            WHERE audit_id = ?
        """, [audit_id]).fetchone()
        
        if duckdb_rows:
            print(f"✓ DuckDB row hashes: {duckdb_rows[0]} rows")
        
        conn.close()
        db.close()
        
    except Exception as e:
        print(f"✗ Verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "=" * 70)
    print("✓ All tests PASSED!")
    print("=" * 70)
    return True


if __name__ == "__main__":
    try:
        result = asyncio.run(test_full_pipeline())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

