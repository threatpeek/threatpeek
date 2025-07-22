from typing import Optional, Dict
from pydantic import BaseModel

class URLScanRequest(BaseModel):
    urls: list[str]

class URLScanResponse(BaseModel):
    url: str
    status: str
    details: str
    vendors: Optional[Dict[str, str]] = None  # Add this field for vendor verdicts