from pydantic import BaseModel
from datetime import datetime

class AuditResponse(BaseModel):
    id: str
    filename: str
    sha256_hash: str
    previous_hash: str | None
    upload_time: datetime
    file_size: int
    status: str
