from __future__ import annotations

from pydantic import BaseModel, Field


class Phase2Payload(BaseModel):
    Target_User: str = Field(default="")
    Notes: str = Field(default="")
    Lineage: str = Field(default="")


class LockRequest(BaseModel):
    Lineage: str


class ExtendRequest(BaseModel):
    Lineage: str
    seconds: int = 30


class RemoveRequest(BaseModel):
    Lineage: str


class GraphQLQueryRequest(BaseModel):
    depth: int = 1
    Target_User: str = Field(default="")
    limit: int = 1000
    offset: int = 0

