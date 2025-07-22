from fastapi import APIRouter
from urllib.parse import urlparse, quote
import re
import httpx
import socket
import os
from dotenv import load_dotenv
from typing import List
from models.scan_models import URLScanRequest, URLScanResponse
from logger import logger, log_request
from utils.ssl_check import async_ssl_check
from utils.analysis_helpers import is_high_entropy
import base64

router = APIRouter()
load_dotenv()

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

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3/urls"


async def query_virustotal(url: str) -> tuple[str, str, dict]:
    try:
        async with httpx.AsyncClient() as client:
            headers = {
                "x-apikey": VT_API_KEY
            }

            # Step 1: Submit URL to VT (optional, but good for new URLs)
            post_resp = await client.post(
                VT_BASE_URL,
                headers=headers,
                data={"url": url}
            )

            if post_resp.status_code != 200:
                return "suspicious", f"VirusTotal POST failed: {post_resp.status_code}", {}

            # Step 2: Encode the URL for GET request
            url_bytes = url.encode("utf-8")
            b64_url = base64.urlsafe_b64encode(url_bytes).decode("utf-8").rstrip("=")

            # Step 3: Get the scan result using the encoded URL
            get_resp = await client.get(f"{VT_BASE_URL}/{b64_url}", headers=headers)

            if get_resp.status_code != 200:
                return "suspicious", f"VirusTotal GET failed: {get_resp.status_code}", {}

            result = get_resp.json()
            stats = result["data"]["attributes"]["last_analysis_stats"]
            vendor_results = result["data"]["attributes"]["last_analysis_results"]
            

            
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)

            if malicious_count > 0:
                status = "malicious"
                detail = f"VirusTotal flagged as malicious by {malicious_count} engines."
            elif suspicious_count > 0:
                status = "suspicious"
                detail = f"VirusTotal flagged as suspicious by {suspicious_count} engines."
            else:
                status = "clean"
                detail = "VirusTotal scan found no threats."

            # Collect vendor verdicts
            vendors = {vendor: res["category"] for vendor, res in vendor_results.items()}
            logger.info(f"VENDORS: {vendors}")
            return status, detail, vendors

    except Exception as e:
        return "suspicious", f"VirusTotal query failed: {e}", {}


async def enhanced_threat_analysis(url: str) -> tuple[str, str]:
    """Custom analysis using HTTP response, headers, blacklist, etc."""
    try:
        async with httpx.AsyncClient(timeout=5.0, headers=HEADERS, follow_redirects=True) as client:
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

        if re.search(r"(<script>|</script>|%3Cscript%3E|%3C%2Fscript%3E)", path, re.IGNORECASE):
            return "suspicious", "URL path includes potential XSS payload."

        if len(path) > 100:
            return "suspicious", "URL path is unusually long — possible obfuscation."

        code = response.status_code
        if code in (200, 301, 302, 307, 308):
            return "clean", f"Responded with status {code} — normal behavior."
        elif code == 403:
            return "suspicious", "Returned 403 Forbidden — possibly a trap or restricted."
        elif code == 404:
            return "suspicious", "Returned 404 Not Found — possibly phishing."
        elif code in (401, 407):
            return "suspicious", f"Returned auth error {code}"
        elif 500 <= code < 600:
            return "suspicious", f"Server error {code}"
        else:
            return "suspicious", f"Unexpected status code {code}"

    except httpx.RequestError as e:
        return "suspicious", f"Request error: {e}"


@router.post("/scan_urls", response_model=List[URLScanResponse])
async def scan_urls(request: URLScanRequest):
    results = []

    for url in request.urls:
        url = url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        # Validate domain before DNS resolution
        if not domain or domain.startswith('.') or domain.endswith('.'):
            results.append(URLScanResponse(
                url=url,
                status="invalid",
                details="Invalid or empty domain in URL"
            ))
            continue

        # Step 1: DNS resolution
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            results.append(URLScanResponse(
                url=url,
                status="invalid",
                details=f"DNS resolution failed for {domain}"
            ))
            continue

        # Step 2: SSL check
        ssl_ok, ssl_details = await async_ssl_check(domain)
        if not ssl_ok:
            results.append(URLScanResponse(
                url=url,
                status="suspicious",
                details="SSL issue: " + " | ".join(ssl_details)
            ))
            continue

        # Step 3: High-entropy check
        if is_high_entropy(path):
            results.append(URLScanResponse(
                url=url,
                status="suspicious",
                details="High entropy in URL path — possible obfuscation."
            ))
            continue

        # Step 4: VirusTotal threat intelligence
        vt_status, vt_detail, vt_vendors = await query_virustotal(url)
        if vt_status in ["malicious", "suspicious"]:
            log_request(url, vt_status, vt_detail)
            results.append(URLScanResponse(
                url=url,
                status=vt_status,
                details=vt_detail,
                vendors=vt_vendors  # Return vendor verdicts to frontend
            ))
            continue

        # Step 5: Local enhanced analysis
        status, detail = await enhanced_threat_analysis(url)
        log_request(url, status, detail)
        results.append(URLScanResponse(url=url, status=status, details=detail))

    return results