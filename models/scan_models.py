from typing import Optional, Dict, List
from pydantic import BaseModel, Field, validator
from urllib.parse import urlparse
import re

class URLScanRequest(BaseModel):
    urls: List[str] = Field(
        ..., 
        min_items=1, 
        max_items=500,
        description="List of URLs to scan (max 500)"
    )
    
    @validator('urls')
    def validate_urls(cls, v):
        cleaned_urls = []
        for url in v:
            if url is None:
                continue
            url = str(url).strip()
            if not url:
                continue

            # Normalize scheme:
            # - If URL already has a scheme (any scheme), keep it as-is.
            # - If no scheme, prefix https://
            if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
                normalized = url
            else:
                normalized = 'https://' + url

            # Do not reject the entire request for malformed URLs here.
            # Let the scanning route perform strict checks per-URL.
            # We will only enforce an absolute max length to prevent abuse.
            if len(normalized) > 4096:
                # Truncate rather than raise; the route will classify as invalid later.
                normalized = normalized[:4096]

            cleaned_urls.append(normalized)

        if not cleaned_urls:
            raise ValueError("No valid URLs provided")
        return cleaned_urls

class URLScanResponse(BaseModel):
    url: str
    status: str = Field(..., description="clean, suspicious, malicious, or invalid")
    details: str
    confidence: Optional[float] = Field(None, description="Confidence score 0-1")
    vendors: Optional[Dict[str, str]] = None
    timestamp: Optional[str] = None
    
class ScanSummary(BaseModel):
    total_urls: int
    clean: int
    suspicious: int
    malicious: int
    invalid: int
    scan_duration_ms: float
