from typing import List

from pydantic import BaseModel, Field

from models.scan_models import URLScanResponse


class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=160)
    tags: List[str] = Field(default_factory=list, max_length=20)
    note: str = Field("", max_length=4000)
    results: List[URLScanResponse] = Field(..., min_length=1, max_length=500)


class CaseNoteCreateRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=4000)
