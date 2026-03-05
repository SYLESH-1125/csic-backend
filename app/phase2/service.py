"""
Phase 2 Orchestration Service
Coordinates all 6 nodes in the Universal Translator pipeline
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.core.logging import logger
from app.db.models import AuditLog
from app.phase2.node1_lineage import anchor_lineage, compute_row_hash, log_to_duckdb
from app.phase2.node2_deobfuscation import process_deobfuscation
from app.phase2.node3_drain3 import process_drain3
from app.phase2.node4_ner import process_ner_tagging
from app.phase2.node5_chronograph import process_timestamp_sync
from app.phase2.node6_staging import create_staging_entry, commit_staging, get_staging_preview


def process_file_phase2(
    db: Session,
    audit_id: str,
    file_path: str,
    source_ip: Optional[str] = None
) -> Dict[str, Any]:
    """
    Process file through Phase 2 pipeline (all 6 nodes).
    
    Args:
        db: Database session
        audit_id: Audit log ID from Phase 1
        file_path: Path to WORM-stored file
        source_ip: Source IP address
    
    Returns:
        {
            "status": "staged",
            "staging_id": str,
            "rows_processed": int,
            "preview_url": str
        }
    """
    # Get audit log to retrieve file hash and metadata
    audit_log = db.query(AuditLog).filter(AuditLog.id == audit_id).first()
    if not audit_log:
        raise ValueError(f"Audit log not found: {audit_id}")
    
    source_file_hash = audit_log.sha256_hash
    
    # If file_path not provided, construct from WORM directory + filename
    if not file_path:
        from app.config import settings
        worm_dir = Path(settings.WORM_STORAGE_PATH)
        file_path = str(worm_dir / audit_log.filename)
    
    file_path_obj = Path(file_path)
    
    if not file_path_obj.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Use source_ip from audit_log if not provided
    if not source_ip:
        source_ip = audit_log.source_ip
    
    logger.info(
        f"[Phase2] Payload received: audit_id={audit_id} "
        f"file_path={file_path} source_ip={source_ip} "
        f"file_hash={source_file_hash[:12]}..."
    )
    
    logger.info(f"[Phase2] Starting processing: audit_id={audit_id} file={file_path}")
    
    # Read file and process line by line
    staging_entries = []
    byte_offset = 0
    
    try:
        with open(file_path_obj, 'rb') as f:
            for line_num, line_bytes in enumerate(f, start=1):
                line = line_bytes.decode('utf-8', errors='ignore').strip()
                
                if not line:
                    byte_offset += len(line_bytes)
                    continue
                
                # Node 1: Lineage Anchoring
                row_hash = compute_row_hash(line)
                
                # Option B: Log row hash to DuckDB (lightweight)
                duckdb_row_id = log_to_duckdb(
                    row_hash=row_hash,
                    audit_id=audit_id,
                    row_data={"line_number": line_num, "content": line}
                )
                
                # Option A: Create lineage anchor in SQLite
                anchor = anchor_lineage(
                    db=db,
                    audit_id=audit_id,
                    source_file_hash=source_file_hash,
                    byte_offset=byte_offset,
                    row_data=line,
                    duckdb_row_id=duckdb_row_id
                )
                
                # Node 2: De-obfuscation
                deobf_result = process_deobfuscation(line)
                decoded_payload = deobf_result.get("decoded")
                decode_trace = deobf_result.get("trace", [])
                
                # Use decoded payload if available, otherwise original
                process_text = decoded_payload if decoded_payload else line
                
                # Node 3: DRAIN3 Template Extraction
                drain3_result = process_drain3(db, process_text, audit_id)
                template_id = drain3_result.get("template_id")
                extracted_variables = drain3_result.get("variables", {})
                
                # Node 4: NER Tagging
                ner_result = process_ner_tagging(process_text, drain3_result.get("template"))
                ner_tags = ner_result.get("tags", {})
                
                # Node 5: Timestamp Sync
                from app.phase2.node5_chronograph import extract_timestamp
                
                timestamp_str = extract_timestamp(line, extracted_variables)
                timestamp_result = None
                normalized_timestamp = None
                
                if timestamp_str:
                    timestamp_result = process_timestamp_sync(
                        db=db,
                        timestamp_str=timestamp_str,
                        source_ip=source_ip,
                        log_line=line  # Pass full line for better extraction
                    )
                    # Get datetime object directly (Node 6 will handle conversion)
                    normalized_timestamp = timestamp_result.get("normalized")
                
                # Node 6: Create Staging Entry
                row_data = {
                    "line_number": line_num,
                    "original": line,
                    "decoded": decoded_payload,
                    "template": drain3_result.get("template"),
                    "variables": extracted_variables,
                    "ner_tags": ner_tags,
                    "timestamp": normalized_timestamp
                }
                
                staging = create_staging_entry(
                    db=db,
                    audit_id=audit_id,
                    row_data=row_data,
                    lineage_anchor_id=anchor.id,
                    decoded_payload={"decoded": decoded_payload} if decoded_payload else None,
                    decode_trace=decode_trace,
                    template_id=template_id,
                    extracted_variables=extracted_variables,
                    ner_tags=ner_tags,
                    normalized_timestamp=normalized_timestamp
                )
                
                staging_entries.append(staging.id)
                byte_offset += len(line_bytes)
                
                if line_num % 100 == 0:
                    logger.debug(f"[Phase2] Processed {line_num} lines...")
        
        logger.info(
            f"[Phase2] Processing complete: "
            f"audit_id={audit_id} rows={len(staging_entries)}"
        )
        
        return {
            "status": "staged",
            "staging_ids": staging_entries,
            "rows_processed": len(staging_entries),
            "preview_url": f"/api/phase2/preview/{staging_entries[0]}" if staging_entries else None
        }
    
    except Exception as e:
        logger.error(f"[Phase2] Processing failed: {e}")
        raise


def get_staging_previews(db: Session, audit_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Get previews of all staging entries for an audit.
    
    Args:
        db: Database session
        audit_id: Audit log ID
        limit: Maximum number of previews
    
    Returns:
        List of preview dictionaries
    """
    from app.db.models import StagingArea
    
    staging_entries = (
        db.query(StagingArea)
        .filter(StagingArea.audit_id == audit_id)
        .filter(StagingArea.status == "pending")
        .limit(limit)
        .all()
    )
    
    return [get_staging_preview(db, staging.id) for staging in staging_entries]


def commit_staging_batch(
    db: Session,
    audit_id: str,
    human_overrides: Optional[Dict[str, Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Commit all staging entries for an audit.
    
    Args:
        db: Database session
        audit_id: Audit log ID
        human_overrides: Dictionary mapping staging_id to overrides
    
    Returns:
        Commit result
    """
    from app.db.models import StagingArea
    
    staging_entries = (
        db.query(StagingArea)
        .filter(StagingArea.audit_id == audit_id)
        .filter(StagingArea.status == "pending")
        .all()
    )
    
    committed = []
    failed = []
    
    for staging in staging_entries:
        try:
            overrides = human_overrides.get(staging.id) if human_overrides else None
            result = commit_staging(db, staging.id, overrides)
            committed.append(staging.id)
        except Exception as e:
            logger.error(f"[Phase2] Failed to commit staging {staging.id}: {e}")
            failed.append(staging.id)
    
    return {
        "status": "completed",
        "committed": len(committed),
        "failed": len(failed),
        "committed_ids": committed,
        "failed_ids": failed
    }

