from fastapi import APIRouter
from urllib.parse import urlparse
import re
import httpx
import socket
from typing import List, Tuple
from models.scan_models import URLScanRequest, URLScanResponse
from logger import logger, log_request
from utils.ssl_check import async_ssl_check
from utils.analysis_helpers import is_high_entropy

router = APIRouter()

BLACKLISTED_DOMAINS = {
    "badguy.com",
    "malicious-site.net",
    "phishy.io"
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/115.0.0.0 Safari/537.36"
    )
}

async def enhanced_threat_analysis(url: str) -> Tuple[str, str]:
    """
    Analyze the given URL for potential threats including redirects, blacklist,
    suspicious patterns, and HTTP status codes.

    Returns:
        Tuple[str, str]: status and details string
    """
    try:
        async with httpx.AsyncClient(
            timeout=5.0, headers=HEADERS, follow_redirects=True
        ) as client:
            response = await client.get(url)
            final_url = str(response.url)
            parsed = urlparse(final_url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()

            logger.info(f"Resolved final URL: {final_url}")

            if domain in BLACKLISTED_DOMAINS:
                return "malicious", f"Domain `{domain}` is on the threat blacklist."

            if parsed.scheme not in ("http", "https"):
                return "invalid", f"Unsupported URL scheme: {parsed.scheme}"

            # Detect basic XSS patterns in path
            if re.search(r"(<script>|</script>|%3Cscript%3E|%3C%2Fscript%3E)", path, re.IGNORECASE):
                return "suspicious", "URL path includes potential XSS payload."

            if len(path) > 100:
                return "suspicious", "URL path unusually long — possible obfuscation."

            status_code = response.status_code

            if status_code in {200, 301, 302, 307, 308}:
                return "clean", f"Final URL responded with status code {status_code}. No threat detected."
            elif status_code == 403:
                return "suspicious", "URL returned forbidden (403) — possible restricted content or trap."
            elif status_code == 404:
                return "suspicious", "URL not found (404) — possibly phishing or abandoned."
            elif status_code in {401, 407}:
                return "suspicious", f"Authentication required status code: {status_code}"
            elif 500 <= status_code < 600:
                return "suspicious", f"Server error status code: {status_code}"
            else:
                return "suspicious", f"Unexpected status code: {status_code}"

    except httpx.RequestError as e:
        return "suspicious", f"Request failed. Reason: {e}"

@router.post("/scan_urls", response_model=List[URLScanResponse])
async def scan_urls(request: URLScanRequest) -> List[URLScanResponse]:
    """
    Batch scan URLs and return list of URLScanResponse with status and details.
    """
    results = []

    for raw_url in request.urls:
        url = raw_url.strip()
        if not url:
            continue

        # Ensure scheme presence
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        logger.info(f"Processing URL: {url}")

        # DNS resolution check
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            logger.warning(f"DNS resolution failed for domain: {domain}")
            results.append(URLScanResponse(
                url=url,
                status="invalid",
                details=f"DNS resolution failed for domain `{domain}`."
            ))
            continue

        # SSL check
        ssl_ok, ssl_details = await async_ssl_check(domain)
        if not ssl_ok:
            msg = " | ".join(ssl_details)
            logger.warning(f"SSL check failed for {domain}: {msg}")
            results.append(URLScanResponse(
                url=url,
                status="suspicious",
                details=f"SSL issue: {msg}"
            ))
            continue

        # Entropy check
        if is_high_entropy(path):
            logger.warning(f"High entropy detected in URL path for {url}")
            results.append(URLScanResponse(
                url=url,
                status="suspicious",
                details="High entropy in URL path — possible obfuscation."
            ))
            continue

        # Deep threat analysis
        try:
            status, detail = await enhanced_threat_analysis(url)
            log_request(url, status, detail)
            results.append(URLScanResponse(
                url=url,
                status=status,
                details=detail
            ))
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}", exc_info=True)
            results.append(URLScanResponse(
                url=url,
                status="error",
                details="Internal error occurred during URL analysis."
            ))

    return results