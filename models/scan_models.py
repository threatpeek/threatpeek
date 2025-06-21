from pydantic import BaseModel

class URLScanRequest(BaseModel):
    url: str  # Changed from HttpUrl to str

class URLScanResponse(BaseModel):
    url: str
    status: str
    details: str
