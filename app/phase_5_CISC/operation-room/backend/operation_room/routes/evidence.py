"""API routes for Evidence import and verification."""

from fastapi import APIRouter, HTTPException
from operation_room.models.evidence import ImportRequest, VerifyHashRequest
from operation_room.services import evidence_service

router = APIRouter(prefix="/api/cases/{case_id}/evidence", tags=["Evidence"])


@router.get("")
def list_evidence(case_id: str):
    """List all evidence artefacts and their hashes for a case."""
    try:
        return evidence_service.list_evidence(case_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/import", status_code=201)
async def import_evidence(case_id: str, payload: ImportRequest):
    """Import logs from the NLP agent, hash and store them."""
    try:
        data = payload.model_dump()
        return await evidence_service.import_evidence(case_id, data)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/verify")
def verify_hash(case_id: str, payload: VerifyHashRequest):
    """Re‑compute the hash of a stored artefact and verify integrity."""
    try:
        return evidence_service.verify_evidence_hash(case_id, payload.hash_id)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc))
