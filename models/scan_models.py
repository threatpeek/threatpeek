from typing import List
from pydantic import BaseModel, HttpUrl

class URLScanRequest(BaseModel):
    # Accepts a list of URLs (strings) for batch scanning
    urls: List[str]

class URLScanResponse(BaseModel):
    url: str        # The URL scanned
    status: str     # Status like clean, suspicious, malicious, invalid, error
    details: str    # Explanation/details of the scan result