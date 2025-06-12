from fastapi import FastAPI, Request
from scanner.threat_scanner import ThreatScanner

app = FastAPI(title="ThreatPeek PH", version="0.1")

@app.get("/")
def read_root():
    return {"message": "ThreatPeek PH API is live."}

@app.get("/scan/")
def scan_url(url: str):
    scanner = ThreatScanner(url)
    result = scanner.run_all()
    return result
