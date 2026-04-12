"""Pydantic models for evidence / log import operations."""

from pydantic import BaseModel, Field


class ImportRequest(BaseModel):
    """Request to import logs for a case."""
    source_type: str = Field(..., description="AUTH, VPN, FW, DB, APP, EPP, FILE")
    time_start: str = Field(..., description="ISO‑8601 start timestamp")
    time_end: str = Field(..., description="ISO‑8601 end timestamp")
    target_actors: list[str] = Field(default_factory=list)
    target_systems: list[str] = Field(default_factory=list)
    query_text: str = Field(default="", description="Optional custom NLP query override")
    justification: str = Field(default="Initial evidence collection")


class EvidenceRecord(BaseModel):
    """A single evidence artefact with its hash."""
    hash_id: str
    case_id: str
    artefact_name: str
    artefact_type: str
    hash_algorithm: str
    hash_value: str
    record_count: int
    byte_size: int
    created_at: str
    created_by: str


class ImportResult(BaseModel):
    """Result returned after a successful import."""
    import_batch_id: str
    artefact_name: str
    record_count: int
    byte_size: int
    hash_algorithm: str
    hash_value: str
    coc_event_id: str
    message: str


class VerifyHashRequest(BaseModel):
    """Request to verify the integrity of an artefact."""
    hash_id: str


class VerifyHashResult(BaseModel):
    """Result of hash verification."""
    hash_id: str
    artefact_name: str
    stored_hash: str
    computed_hash: str
    match: bool
    message: str
