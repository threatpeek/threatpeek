from pydantic import BaseModel, HttpUrl

class URLScanRequest(BaseModel):
    url: HttpUrl

class URLScanResponse(BaseModel):
    url: str
    status: str
    details: str
