# utils/virustotal.py

import httpx
import base64
import asyncio
import os
from typing import Tuple, Dict
from time import time
from config import config

VT_API_KEY = os.getenv("VT_API_KEY")

headers = {
    "x-apikey": VT_API_KEY,
    "Content-Type": "application/x-www-form-urlencoded"
}

# Simple in-memory TTL cache for VT results
_vt_cache: Dict[str, Dict] = {}

def _vt_cache_get(key: str):
    entry = _vt_cache.get(key)
    if not entry:
        return None
    if entry.get("expires", 0) > time():
        return entry
    # expired
    try:
        del _vt_cache[key]
    except KeyError:
        pass
    return None

def _vt_cache_set(key: str, status: str, detail: str, vendors: Dict[str, str]):
    ttl = getattr(config, "VT_CACHE_TTL_SECONDS", 900) or 900
    _vt_cache[key] = {
        "status": status,
        "detail": detail,
        "vendors": vendors,
        "expires": time() + ttl,
    }

async def submit_url_to_vt(url: str) -> str:
    async with httpx.AsyncClient() as client:
        response = await client.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=f"url={url}")
        response.raise_for_status()
        return response.json()["data"]["id"]

async def get_vt_report(vt_id: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://www.virustotal.com/api/v3/urls/{vt_id}", headers=headers)
        response.raise_for_status()
        return response.json()

async def query_virustotal(url: str) -> Tuple[str, str, Dict[str, str]]:
    """Submit a URL and fetch its report from VirusTotal.
    Returns a tuple (status, detail, vendors).
    status: "malicious" | "suspicious" | "clean" | "suspicious" on VT errors/missing key
    detail: human readable reason
    vendors: mapping of vendor -> category (present when VT succeeds)
    """
    if not VT_API_KEY:
        return "suspicious", "VT API key missing", {}

    key = url.strip().lower()
    cached = _vt_cache_get(key)
    if cached:
        return cached["status"], cached["detail"], cached.get("vendors") or {}

    try:
        async with httpx.AsyncClient() as client:
            vt_headers = {"x-apikey": VT_API_KEY}
            # Step 1: Submit URL
            post_resp = await client.post("https://www.virustotal.com/api/v3/urls", headers=vt_headers, data={"url": url})
            if post_resp.status_code != 200:
                return "suspicious", f"VT POST failed: {post_resp.status_code}", {}

            # Step 2: Encode URL key & GET report
            b64_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            get_resp = await client.get(f"https://www.virustotal.com/api/v3/urls/{b64_url}", headers=vt_headers)
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
                status, detail = "malicious", f"Flagged as malicious by {malicious} VT engines."
            elif suspicious > 0:
                status, detail = "suspicious", f"Flagged as suspicious by {suspicious} VT engines."
            else:
                status, detail = "clean", "No threats found by VirusTotal."

            # Cache successful lookups only (with vendors present)
            _vt_cache_set(key, status, detail, vendors)
            return status, detail, vendors
    except Exception as e:
        return "suspicious", f"VT query error: {e}", {}
