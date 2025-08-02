from fastapi import APIRouter
from urllib.parse import urlparse
import re
import httpx
import socket
import os
from dotenv import load_dotenv
from typing import List
import base64

from models.scan_models import URLScanRequest, URLScanResponse
from logger import logger, log_request
from utils.ssl_check import async_ssl_check
from utils.analysis_helpers import is_high_entropy
from fastapi.responses import Response
import csv
import io
import json
from datetime import datetime

router = APIRouter()
load_dotenv()

BLACKLISTED_DOMAINS = ["badguy.com", "malicious-site.net", "phishy.io"]
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/115.0.0.0 Safari/537.36"
}

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3/urls"


async def query_virustotal(url: str) -> tuple[str, str, dict]:
    try:
        async with httpx.AsyncClient() as client:
            headers = {"x-apikey": VT_API_KEY}

            # Step 1: Submit URL
            post_resp = await client.post(VT_BASE_URL, headers=headers, data={"url": url})
            if post_resp.status_code != 200:
                return "suspicious", f"VT POST failed: {post_resp.status_code}", {}

            # Step 2: Encode & request report
            b64_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            get_resp = await client.get(f"{VT_BASE_URL}/{b64_url}", headers=headers)
            if get_resp.status_code != 200:
                return "suspicious", f"VT GET failed: {get_resp.status_code}", {}

            data = get_resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            vendors = {
                vendor: res["category"]
                for vendor, res in data["data"]["attributes"]["last_analysis_results"].items()
            }

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                return "malicious", f"Flagged as malicious by {malicious} VT engines.", vendors
            elif suspicious > 0:
                return "suspicious", f"Flagged as suspicious by {suspicious} VT engines.", vendors
            else:
                return "clean", "No threats found by VirusTotal.", vendors

    except Exception as e:
        return "suspicious", f"VT query error: {e}", {}


async def enhanced_threat_analysis(url: str) -> tuple[str, str]:
    try:
        async with httpx.AsyncClient(timeout=5.0, headers=HEADERS, follow_redirects=True) as client:
            resp = await client.get(url)
            parsed = urlparse(str(resp.url))
            domain, path = parsed.netloc.lower(), parsed.path.lower()

        if domain in BLACKLISTED_DOMAINS:
            return "malicious", f"Domain `{domain}` is blacklisted."
        if parsed.scheme not in ("http", "https"):
            return "invalid", f"Unsupported scheme: {parsed.scheme}"
        if re.search(r"(<script>|</script>|%3Cscript%3E|%3C%2Fscript%3E)", path, re.IGNORECASE):
            return "suspicious", "Possible XSS payload."
        if len(path) > 100:
            return "suspicious", "URL path too long — suspicious."
        
        code = resp.status_code
        if code in (200, 301, 302, 307, 308):
            return "clean", f"Responded with {code} — normal behavior."
        elif code in (403, 404, 401, 407) or (500 <= code < 600):
            return "suspicious", f"Returned error status: {code}"
        return "suspicious", f"Unexpected status code: {code}"

    except httpx.RequestError as e:
        return "suspicious", f"Request error: {e}"


@router.post("/scan_urls", response_model=List[URLScanResponse])
async def scan_urls(request: URLScanRequest):
    results = []

    for url in request.urls:
        url = url.strip()
        if not url.startswith("http"):
            url = "https://" + url
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        if not domain or domain.startswith('.') or domain.endswith('.'):
            results.append(URLScanResponse(url=url, status="invalid", details="Invalid domain"))
            continue

        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            results.append(URLScanResponse(url=url, status="invalid", details="DNS resolution failed"))
            continue

        ssl_ok, ssl_issues = await async_ssl_check(domain)
        if not ssl_ok:
            results.append(URLScanResponse(url=url, status="suspicious", details="SSL: " + " | ".join(ssl_issues)))
            continue

        if is_high_entropy(path):
            results.append(URLScanResponse(url=url, status="suspicious", details="High entropy in path"))
            continue

        vt_status, vt_detail, vendors = await query_virustotal(url)
        # Always trust VirusTotal verdicts
        log_request(url, vt_status, vt_detail)
        results.append(URLScanResponse(url=url, status=vt_status, details=vt_detail, vendors=vendors))

    return results


@router.post("/export/csv")
async def export_scan_results_csv(request: URLScanRequest):
    """Export scan results as CSV file"""
    results = await scan_urls(request)  # Reuse the scan logic
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['URL', 'Status', 'Details', 'Timestamp'])
    
    # Write data rows
    timestamp = datetime.utcnow().isoformat()
    for result in results:
        writer.writerow([
            result.url,
            result.status,
            result.details,
            timestamp
        ])
    
    csv_content = output.getvalue()
    output.close()
    
    # Return as downloadable file
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatpeek_scan_results.csv"}
    )


@router.post("/export/json")
async def export_scan_results_json(request: URLScanRequest):
    """Export scan results as JSON file"""
    results = await scan_urls(request)  # Reuse the scan logic
    
    # Create JSON structure
    export_data = {
        "scan_timestamp": datetime.utcnow().isoformat(),
        "total_urls": len(results),
        "results": [
            {
                "url": result.url,
                "status": result.status,
                "details": result.details,
                "vendors": result.vendors
            }
            for result in results
        ]
    }
    
    json_content = json.dumps(export_data, indent=2)
    
    # Return as downloadable file
    return Response(
        content=json_content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=threatpeek_scan_results.json"}
    )
