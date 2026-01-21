from fastapi import APIRouter
from urllib.parse import urlparse
import re
import httpx
import socket
import os
from dotenv import load_dotenv
from typing import List
import base64
from pydantic import BaseModel
from models.scan_models import URLScanRequest, URLScanResponse
from logger import logger, log_request
from utils.ssl_check import async_ssl_check
from utils.analysis_helpers import is_high_entropy
from utils.virustotal import query_virustotal
from fastapi.responses import Response
import csv
import io
import json
from datetime import datetime
from config import config
from utils.rank_provider import (
    get_global_rank,
    rank_bucket_for,
    registrable_domain,
    is_ready as rank_ready,
)

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


# Legacy compatibility route to support tests/clients using singular endpoint
class LegacyScanRequest(BaseModel):
    url: str

@router.post("/scan_url")
async def scan_url_compat(payload: LegacyScanRequest):
    raw = (payload.url or "").strip()
    if not raw:
        # Invalid when empty/whitespace
        result = {"url": raw, "status": "invalid", "details": "Invalid domain"}
        log_request(raw, result["status"], result["details"])
        return result

    url = raw if "://" in raw else "https://" + raw
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path or ""

    # Ranking info (registrable domain)
    rd = registrable_domain(domain) if domain else None
    gr, rsrc = get_global_rank(rd) if rd else (None, None)
    rb = rank_bucket_for(gr) if gr else None

    # Unsupported scheme → suspicious (per tests)
    if parsed.scheme not in ("http", "https"):
        result = {"url": url, "status": "suspicious", "details": f"Unsupported scheme: {parsed.scheme}", "global_rank": gr, "rank_bucket": rb, "rank_source": rsrc}
        log_request(url, result["status"], result["details"])
        return result

    # Basic domain sanity (must contain a dot and only valid hostname chars)
    if (
        not domain or domain.startswith('.') or domain.endswith('.') or
        '.' not in domain or not re.fullmatch(r'[A-Za-z0-9.-]+', domain)
    ):
        result = {"url": url, "status": "invalid", "details": "Invalid domain", "global_rank": gr, "rank_bucket": rb, "rank_source": rsrc}
        log_request(url, result["status"], result["details"])
        return result

    # Blacklist
    if domain in BLACKLISTED_DOMAINS:
        result = {"url": url, "status": "malicious", "details": f"Domain `{domain}` is blacklisted", "global_rank": gr, "rank_bucket": rb, "rank_source": rsrc}
        log_request(url, result["status"], result["details"])
        return result

    # XSS payload
    if re.search(r"(<script>|</script>|%3Cscript%3E|%3C%2Fscript%3E)", path, re.IGNORECASE):
        result = {"url": url, "status": "suspicious", "details": "XSS payload detected", "global_rank": gr, "rank_bucket": rb, "rank_source": rsrc}
        log_request(url, result["status"], result["details"])
        return result

    # Long path
    if len(path) > 100:
        result = {"url": url, "status": "suspicious", "details": "URL path unusually long", "global_rank": gr, "rank_bucket": rb, "rank_source": rsrc}
        log_request(url, result["status"], result["details"])
        return result

    # High-entropy path
    if is_high_entropy(path):
        result = {"url": url, "status": "suspicious", "details": "High entropy in path", "global_rank": gr, "rank_bucket": rb, "rank_source": rsrc}
        log_request(url, result["status"], result["details"])
        return result

    # DNS resolution check: classify unresolvable domains as invalid
    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        result = {"url": url, "status": "invalid", "details": "DNS resolution failed", "global_rank": gr, "rank_bucket": rb, "rank_source": rsrc}
        log_request(url, result["status"], result["details"])
        return result

    # SSL check for HTTPS
    if parsed.scheme == "https":
        ssl_ok, ssl_issues = await async_ssl_check(domain)
        if not ssl_ok:
            detail = "SSL: " + " | ".join(ssl_issues)
            result = {"url": url, "status": "suspicious", "details": detail, "global_rank": gr, "rank_bucket": rb, "rank_source": rsrc}
            log_request(url, result["status"], result["details"])
            return result

    # Lightweight HTTP GET to observe final status
    try:
        async with httpx.AsyncClient(timeout=5.0, headers=HEADERS, follow_redirects=True) as client:
            resp = await client.get(url)
            code = resp.status_code
            final_url = str(resp.url)
            if code in (200, 301, 302, 307, 308):
                result = {"url": final_url, "status": "clean", "details": "No threat detected", "global_rank": gr, "rank_bucket": rb, "rank_source": rsrc}
            elif code in (401, 403, 404, 407) or (500 <= code < 600):
                result = {"url": final_url, "status": "suspicious", "details": f"Returned error status: {code}", "global_rank": gr, "rank_bucket": rb, "rank_source": rsrc}
            else:
                result = {"url": final_url, "status": "suspicious", "details": f"Unexpected status code: {code}", "global_rank": gr, "rank_bucket": rb, "rank_source": rsrc}
            log_request(final_url, result["status"], result["details"])
            return result
    except httpx.RequestError as e:
        result = {"url": url, "status": "suspicious", "details": f"Request error: {e}", "global_rank": gr, "rank_bucket": rb, "rank_source": rsrc}
        log_request(url, result["status"], result["details"])
        return result


@router.post("/scan_urls", response_model=List[URLScanResponse])
async def scan_urls(request: URLScanRequest):
    results: List[URLScanResponse] = []

    # Per-request caches
    dns_cache: dict[str, bool] = {}
    ssl_cache: dict[str, tuple[bool, list[str]]] = {}

    for raw in request.urls:
        url = raw.strip()
        if "://" not in url:
            url = "https://" + url

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = (parsed.path or "").lower()

        # Ranking precompute
        rd = registrable_domain(domain) if domain else None
        gr, rsrc = get_global_rank(rd) if rd else (None, None)
        rb = rank_bucket_for(gr) if gr else None

        # 1) Protocol check
        if parsed.scheme not in ("http", "https"):
            status = "suspicious"
            detail = f"Unsupported scheme: {parsed.scheme} — non-HTTP protocol"
            log_request(url, status, detail)
            results.append(URLScanResponse(url=url, status=status, details=detail, global_rank=gr, rank_bucket=rb, rank_source=rsrc))
            continue

        # 2) Domain sanity
        if not domain or domain.startswith('.') or domain.endswith('.'):
            status = "invalid"
            detail = "Invalid domain"
            log_request(url, status, detail)
            results.append(URLScanResponse(url=url, status=status, details=detail, global_rank=gr, rank_bucket=rb, rank_source=rsrc))
            continue

        # 3) DNS resolution (per-request cache)
        dns_ok = dns_cache.get(domain)
        if dns_ok is None:
            try:
                socket.gethostbyname(domain)
                dns_ok = True
            except socket.gaierror:
                dns_ok = False
            dns_cache[domain] = dns_ok
        if not dns_ok:
            status = "invalid"
            detail = "DNS resolution failed"
            log_request(url, status, detail)
            results.append(URLScanResponse(url=url, status=status, details=detail, global_rank=gr, rank_bucket=rb, rank_source=rsrc))
            continue

        # 4) SSL check for HTTPS (per-request cache)
        if parsed.scheme == "https":
            cached_ssl = ssl_cache.get(domain)
            if cached_ssl is None:
                cached_ssl = await async_ssl_check(domain)
                ssl_cache[domain] = cached_ssl
            ssl_ok, ssl_issues = cached_ssl
            if not ssl_ok:
                status = "suspicious"
                detail = "SSL: " + " | ".join(ssl_issues)
                log_request(url, status, detail)
                results.append(URLScanResponse(url=url, status=status, details=detail, global_rank=gr, rank_bucket=rb, rank_source=rsrc))
                continue

        # 5) Path heuristics
        if len(path) > config.MAX_PATH_LENGTH:
            status = "suspicious"
            detail = "URL path unusually long"
            log_request(url, status, detail)
            results.append(URLScanResponse(url=url, status=status, details=detail, global_rank=gr, rank_bucket=rb, rank_source=rsrc))
            continue

        if is_high_entropy(path):
            status = "suspicious"
            detail = "High entropy in path"
            log_request(url, status, detail)
            results.append(URLScanResponse(url=url, status=status, details=detail, global_rank=gr, rank_bucket=rb, rank_source=rsrc))
            continue

        # 6) VirusTotal (authoritative verdict after heuristics pass)
        vt_status, vt_detail, vendors = await query_virustotal(url)
        log_request(url, vt_status, vt_detail)
        include_vendors = vendors if vt_status in ("malicious", "suspicious") and vendors else None
        # Extra audit logging: list vendors that flagged the URL
        if include_vendors:
            flagged = [f"{k}:{v}" for k, v in include_vendors.items() if v not in ("harmless", "undetected")]
            if flagged:
                logger.info("Vendors flagged: " + ", ".join(flagged))
        results.append(URLScanResponse(url=url, status=vt_status, details=vt_detail, vendors=include_vendors, global_rank=gr, rank_bucket=rb, rank_source=rsrc))

    return results


@router.post("/export/csv")
async def export_scan_results_csv(request: URLScanRequest):
    """Export scan results as CSV file"""
    results = await scan_urls(request)  # Reuse the scan logic
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['URL', 'Status', 'Details', 'GlobalRank', 'RankBucket', 'Timestamp'])
    
    # Write data rows
    timestamp = datetime.utcnow().isoformat()
    for result in results:
        writer.writerow([
            result.url,
            result.status,
            result.details,
            result.global_rank if getattr(result, 'global_rank', None) is not None else '',
            result.rank_bucket or '',
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


@router.get("/status/config")
async def config_status():
    return {"vt_present": bool(VT_API_KEY), "rank_present": rank_ready()}

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
                "vendors": result.vendors,
                "global_rank": result.global_rank,
                "rank_bucket": result.rank_bucket
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
