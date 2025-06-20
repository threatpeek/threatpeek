from fastapi import APIRouter
from pydantic import HttpUrl
from urllib.parse import urlparse
import re
import httpx
from models.scan_models import URLScanRequest, URLScanResponse
from logger import logger, log_request
from utils.ssl_check import async_ssl_check
from utils.analysis_helpers import is_high_entropy

router = APIRouter()

BLACKLISTED_DOMAINS = [
    "badguy.com",
    "malicious-site.net",
    "phishy.io"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/115.0.0.0 Safari/537.36"
}


async def enhanced_threat_analysis(url: str) -> tuple[str, str]:
    url_str = str(url)
    parsed = urlparse(url_str)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    if domain in BLACKLISTED_DOMAINS:
        return "malicious", f"Domain `{domain}` is on the threat blacklist."

    if parsed.scheme not in ("http", "https"):
        return "invalid", f"Unsupported URL scheme: {parsed.scheme}"

    if re.search(r"(<script>|</script>|%3Cscript%3E|%3C%2Fscript%3E)", path, re.IGNORECASE):
        return "suspicious", "URL path includes potential XSS payload."

    try:
        async with httpx.AsyncClient(timeout=5.0, headers=HEADERS, follow_redirects=True) as client:
            response = await client.get(url_str)
            status_code = response.status_code

            if status_code in (200, 301, 302, 307, 308):
                if len(path) > 100:
                    return "suspicious", "URL path is unusually long — possible obfuscation."
                return "clean", f"URL responded with status code {status_code}. No threat detected."

            elif status_code == 403:
                return "suspicious", "URL returned forbidden (403) — possible restricted content or trap."

            elif status_code == 404:
                return "suspicious", "URL not found (404) — possibly phishing or abandoned."

            elif status_code in (401, 407):
                return "suspicious", f"URL returned authentication-required status: {status_code}"

            elif 500 <= status_code < 600:
                return "suspicious", f"URL returned server error status code {status_code}"

            else:
                return "suspicious", f"Unexpected status code {status_code}"

    except httpx.RequestError as e:
        return "suspicious", f"Request failed. Reason: {e}"


@router.post("/scan_url", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    url = request.url
    parsed = urlparse(str(url))
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    logger.info(f"Received scan request for URL: {url}")

    # SSL Check
    ssl_ok, ssl_details = await async_ssl_check(domain)
    if not ssl_ok:
        msg = " | ".join(ssl_details)
        logger.warning(f"SSL issue: {msg}")
        return URLScanResponse(url=url, status="suspicious", details=msg)

    # Entropy Check
    if is_high_entropy(path):
        msg = "High entropy in URL path — possible obfuscation."
        logger.warning(msg)
        return URLScanResponse(url=url, status="suspicious", details=msg)

    # Content/behavioral analysis
    try:
        status, details = await enhanced_threat_analysis(url)
        log_request(url, status, details)
        return URLScanResponse(url=str(url), status=status, details=details)

    except Exception as e:
        logger.error(f"Unexpected error while scanning: {e}", exc_info=True)
        return URLScanResponse(
    url=str(url),
    status="error",
    details="An internal error occurred during URL analysis."
)


