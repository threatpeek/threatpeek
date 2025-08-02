from typing import Optional, Dict, List
from pydantic import BaseModel, Field, validator
from urllib.parse import urlparse
import re

class URLScanRequest(BaseModel):
    urls: List[str] = Field(
        ..., 
        min_items=1, 
        max_items=10,
        description="List of URLs to scan (max 10)"
    )
    
    @validator('urls')
    def validate_urls(cls, v):
        cleaned_urls = []
        for url in v:
            url = url.strip()
            if not url:
                continue
                
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Basic URL format validation
            try:
                parsed = urlparse(url)
                if not parsed.netloc:
                    raise ValueError(f"Invalid URL format: {url}")
                if len(url) > 2048:  # RFC 2616 recommends this limit
                    raise ValueError(f"URL too long: {url}")
            except Exception as e:
                raise ValueError(f"Invalid URL: {url} - {str(e)}")
                
            cleaned_urls.append(url)
        
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
