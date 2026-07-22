from fastapi import APIRouter, Request
from urllib.parse import urlparse
import re
import httpx
import socket
import os
from dotenv import load_dotenv
from typing import Any, List
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

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
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

def _defang_url_for_csv(url: str) -> str:
    """Defang URL by replacing dots with [.] to reduce accidental clicking in exports."""
    return url.replace(".", "[.]")


async def _inspect_redirect_chain(url: str) -> tuple[List[dict[str, Any]], List[str]]:
    """Follow a URL and return a compact, analyst-friendly redirect trail.

    The final response is included as the last hop so callers can see where the
    request ended even when no redirect occurred. Network failures are evidence,
    not a scan failure: the reputation lookup can still continue.
    """
    try:
        async with httpx.AsyncClient(
            timeout=config.HTTP_TIMEOUT,
            headers=HEADERS,
            follow_redirects=True,
            max_redirects=10,
        ) as client:
            response = await client.get(url)

        responses = [*response.history, response]
        chain = [
            {"url": str(item.url), "status_code": item.status_code}
            for item in responses
        ]
        factors: List[str] = []
        if len(chain) > 1:
            factors.append(f"Followed {len(chain) - 1} redirect hop(s)")

        origin_domain = registrable_domain(urlparse(url).hostname)
        destination_domain = registrable_domain(urlparse(str(response.url)).hostname)
        if origin_domain and destination_domain and origin_domain != destination_domain:
            factors.append(f"Redirected from {origin_domain} to {destination_domain}")
        if response.status_code >= 400:
            factors.append(f"Final HTTP response was {response.status_code}")
        return chain, factors
    except httpx.RequestError as exc:
        return [], [f"Redirect inspection failed: {exc.__class__.__name__}"]


def _risk_assessment(
    status: str,
    *,
    base_factors: List[str] | None = None,
    vendors: dict[str, str] | None = None,
) -> tuple[int, List[str]]:
    """Create a bounded score with reasons that can be shown directly to users."""
    factors = list(base_factors or [])
    if status == "invalid":
        return 0, factors or ["URL could not be scanned"]

    score = 0
    if status == "malicious":
        score += 70
        factors.insert(0, "VirusTotal classified this URL as malicious")
    elif status == "suspicious":
        score += 40

    vendor_values = [str(value).lower() for value in (vendors or {}).values()]
    malicious_count = vendor_values.count("malicious")
    suspicious_count = vendor_values.count("suspicious")
    if malicious_count:
        score += min(25, malicious_count * 8)
        factors.append(f"{malicious_count} VirusTotal vendor(s) marked it malicious")
    if suspicious_count:
        score += min(15, suspicious_count * 4)
        factors.append(f"{suspicious_count} VirusTotal vendor(s) marked it suspicious")

    for factor in factors:
        if factor.startswith("Redirected from"):
            score += 15
        elif factor.startswith("Followed "):
            score += 5
        elif factor.startswith("Final HTTP response was"):
            score += 10
        elif factor.startswith("SSL:"):
            score += 30
        elif "entropy" in factor.lower():
            score += 25
        elif "path unusually long" in factor.lower():
            score += 15

    return min(score, 100), factors or ["No risk indicators observed"]


def _scan_response(
    *,
    url: str,
    status: str,
    details: str,
    global_rank: int | None,
    rank_bucket: str | None,
    rank_source: str | None,
    vendors: dict[str, str] | None = None,
    risk_factors: List[str] | None = None,
    redirect_chain: List[dict[str, Any]] | None = None,
) -> URLScanResponse:
    score, factors = _risk_assessment(status, base_factors=risk_factors, vendors=vendors)
    return URLScanResponse(
        url=url,
        status=status,
        details=details,
        vendors=vendors,
        global_rank=global_rank,
        rank_bucket=rank_bucket,
        rank_source=rank_source,
        risk_score=score,
        risk_factors=factors,
        redirect_chain=redirect_chain or [],
    )



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
@limiter.limit(f"{config.RATE_LIMIT_PER_MINUTE}/minute")
async def scan_url_compat(request: Request, payload: LegacyScanRequest):
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


async def _do_scan_urls(payload: URLScanRequest) -> List[URLScanResponse]:
    """Core scanning logic, extracted so export endpoints can call it directly
    without triggering the rate limiter a second time.
    """
    results: List[URLScanResponse] = []

    # Per-request caches
    dns_cache: dict[str, bool] = {}
    ssl_cache: dict[str, tuple[bool, list[str]]] = {}

    for raw in payload.urls:
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
            results.append(_scan_response(url=url, status=status, details=detail, global_rank=gr, rank_bucket=rb, rank_source=rsrc, risk_factors=[detail]))
            continue

        # 2) Domain sanity
        if not domain or domain.startswith('.') or domain.endswith('.'):
            status = "invalid"
            detail = "Invalid domain"
            log_request(url, status, detail)
            results.append(_scan_response(url=url, status=status, details=detail, global_rank=gr, rank_bucket=rb, rank_source=rsrc, risk_factors=[detail]))
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
            results.append(_scan_response(url=url, status=status, details=detail, global_rank=gr, rank_bucket=rb, rank_source=rsrc, risk_factors=[detail]))
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
                results.append(_scan_response(url=url, status=status, details=detail, global_rank=gr, rank_bucket=rb, rank_source=rsrc, risk_factors=[detail]))
                continue

        # 5) Path heuristics
        if len(path) > config.MAX_PATH_LENGTH:
            status = "suspicious"
            detail = "URL path unusually long"
            log_request(url, status, detail)
            results.append(_scan_response(url=url, status=status, details=detail, global_rank=gr, rank_bucket=rb, rank_source=rsrc, risk_factors=[detail]))
            continue

        if is_high_entropy(path):
            status = "suspicious"
            detail = "High entropy in path"
            log_request(url, status, detail)
            results.append(_scan_response(url=url, status=status, details=detail, global_rank=gr, rank_bucket=rb, rank_source=rsrc, risk_factors=[detail]))
            continue

        # 6) Follow redirects before reputation lookup, so analysts can see the final destination.
        redirect_chain, redirect_factors = await _inspect_redirect_chain(url)

        # 7) VirusTotal (authoritative verdict after heuristics pass)
        vt_status, vt_detail, vendors = await query_virustotal(url)
        log_request(url, vt_status, vt_detail)
        include_vendors = vendors if vt_status in ("malicious", "suspicious") and vendors else None
        # Extra audit logging: list vendors that flagged the URL
        if include_vendors:
            flagged = [f"{k}:{v}" for k, v in include_vendors.items() if v not in ("harmless", "undetected")]
            if flagged:
                logger.info("Vendors flagged: " + ", ".join(flagged))
        results.append(_scan_response(
            url=url,
            status=vt_status,
            details=vt_detail,
            vendors=include_vendors,
            global_rank=gr,
            rank_bucket=rb,
            rank_source=rsrc,
            risk_factors=[*redirect_factors, vt_detail],
            redirect_chain=redirect_chain,
        ))

    return results


async def scan_urls(payload: URLScanRequest):
    return await _do_scan_urls(payload)

@router.post("/scan_urls", response_model=List[URLScanResponse])
@limiter.limit(f"{config.RATE_LIMIT_PER_MINUTE}/minute")
async def scan_urls_endpoint(request: Request, payload: URLScanRequest):
    return await _do_scan_urls(payload)


@router.post("/export/csv")
@limiter.limit(f"{config.RATE_LIMIT_PER_MINUTE}/minute")
async def export_scan_results_csv(request: Request, payload: URLScanRequest):
    """Export scan results as CSV file"""
    results = await _do_scan_urls(payload)
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['URL', 'Status', 'RiskScore', 'RiskFactors', 'Details', 'GlobalRank', 'RankBucket', 'Timestamp'])
    
    # Write data rows
    timestamp = datetime.utcnow().isoformat()
    for result in results:
        writer.writerow([
            _defang_url_for_csv(result.url),
            result.status,
            result.risk_score,
            " | ".join(result.risk_factors),
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
@limiter.limit(f"{config.RATE_LIMIT_PER_MINUTE}/minute")
async def export_scan_results_json(request: Request, payload: URLScanRequest):
    """Export scan results as JSON file"""
    results = await _do_scan_urls(payload)
    
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
                "rank_bucket": result.rank_bucket,
                "risk_score": result.risk_score,
                "risk_factors": result.risk_factors,
                "redirect_chain": result.redirect_chain,
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
