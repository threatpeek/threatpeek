from fastapi import APIRouter
from pydantic import HttpUrl
from models.scan_models import URLScanRequest, URLScanResponse
import re
from urllib.parse import urlparse
import httpx
import requests
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import certifi
from logger import logger, log_request
from datetime import datetime, timezone




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



def analyze_ssl_cert(hostname: str, port: int = 443) -> tuple[bool, list[str]]:
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                if not_after:
                    exp_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    if exp_date < datetime.now(timezone.utc):

                        return False, ["SSL certificate expired."]
                return True, []
    except ssl.SSLError as e:
        return False, [f"SSL check failed: {str(e)}"]
    except Exception as e:
        return False, [f"SSL check failed: {str(e)}"]



def enhanced_threat_analysis(url: str) -> tuple[str, str]:

    ssl_valid = True
    ssl_messages = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    if domain in BLACKLISTED_DOMAINS:
        return "malicious", f"Domain `{domain}` is on the threat blacklist."

    if parsed.scheme not in ("http", "https"):
        return "invalid", f"Unsupported URL scheme: {parsed.scheme}"
    
    # SSL Certificate Check
    ssl_valid, ssl_messages = analyze_ssl_cert(domain)
    if not ssl_valid:
        return "suspicious", " | ".join(ssl_messages)



    # Pre-request XSS detection — no need to ping server if obvious
    if re.search(r"(<script>|</script>|%3Cscript%3E|%3C%2Fscript%3E)", path, re.IGNORECASE):
        return "suspicious", "URL path includes potential XSS payload."

    try:
        response = requests.get(url, headers=HEADERS, timeout=5)
        status_code = response.status_code

        if status_code == 200:
            if len(path) > 100:
                return "suspicious", "URL path is unusually long — possible obfuscation."
            return "clean", "No known threat indicators found. URL appears safe."

        elif status_code == 403:
            return "suspicious", "URL returned authentication required or forbidden status code 403."

        elif status_code == 404:
            return "suspicious", "URL not found (404) — possibly phishing or dead link."

        elif status_code == 401 or status_code == 407:
            return "suspicious", f"URL returned authentication or proxy auth required status code {status_code}."

        elif 500 <= status_code < 600:
            return "suspicious", f"URL returned server error status code {status_code}"

        else:
            return "suspicious", f"URL returned unexpected status code {status_code}"

    except requests.RequestException as e:
        return "suspicious", f"URL unreachable, but no obvious threat indicators. Reason: {e}"


@router.post("/scan_url", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    url = str(request.url)
    logger.info(f"Received scan request for URL: {url}")

    try:
        status, details = enhanced_threat_analysis(url)
        log_request(url, status, details)
    except Exception as e:
        logger.error(f"Unexpected error scanning URL {url}: {e}", exc_info=True)
        status = "error"
        details = "An internal error occurred during URL analysis."

    return URLScanResponse(url=url, status=status, details=details)
