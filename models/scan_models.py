# models/scan_models.py
from pydantic import BaseModel, field_validator, HttpUrl

class URLScanRequest(BaseModel):
    url: HttpUrl

    @field_validator("url", mode="before")
    @classmethod
    def ensure_full_url(cls, v):
        if not isinstance(v, str):
            return v
        if not v.startswith(("http://", "https://")):
            return "http://" + v
        return v



class URLScanResponse(BaseModel):
    url: str
    status: str
    details: str
