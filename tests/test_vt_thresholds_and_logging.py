import os
import sys
import base64
import importlib
import pytest
import respx
from httpx import Response

# Ensure project root is on sys.path for imports like utils.*, routes.*, config
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Tests for utils.virustotal.query_virustotal thresholds and details

@pytest.mark.asyncio
@respx.mock
async def test_query_virustotal_malicious_when_meets_or_exceeds_threshold(monkeypatch):
    # Ensure VT key is present for the function path
    import utils.virustotal as vt
    monkeypatch.setattr(vt, "VT_API_KEY", "dummy-key", raising=False)
    # Clear cache to avoid cross-test contamination
    vt._vt_cache.clear()

    # Set thresholds via the imported config instance inside utils.virustotal
    monkeypatch.setattr(vt.config, "VT_MALICIOUS_THRESHOLD", 3, raising=False)
    monkeypatch.setattr(vt.config, "VT_SUSPICIOUS_THRESHOLD", 1, raising=False)

    url = "http://example.com/test"
    b64 = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    # Mock VT API calls
    respx.post("https://www.virustotal.com/api/v3/urls").mock(
        return_value=Response(200, json={"data": {"id": "ignored-by-impl"}})
    )
    respx.get(f"https://www.virustotal.com/api/v3/urls/{b64}").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 3, "suspicious": 0},
                        "last_analysis_results": {
                            "VendorA": {"category": "malicious"},
                            "VendorB": {"category": "harmless"},
                        },
                    }
                }
            },
        )
    )

    status, detail, vendors = await vt.query_virustotal(url)
    assert status == "malicious"
    assert "malicious by 3" in detail
    assert vendors.get("VendorA") == "malicious"


@pytest.mark.asyncio
@respx.mock
async def test_query_virustotal_suspicious_when_below_malicious_threshold_but_meets_suspicious(monkeypatch):
    import utils.virustotal as vt
    monkeypatch.setattr(vt, "VT_API_KEY", "dummy-key", raising=False)
    vt._vt_cache.clear()

    # Set thresholds: malicious requires >= 4, suspicious requires >= 2
    monkeypatch.setattr(vt.config, "VT_MALICIOUS_THRESHOLD", 4, raising=False)
    monkeypatch.setattr(vt.config, "VT_SUSPICIOUS_THRESHOLD", 2, raising=False)

    url = "http://example.com/suspicious"
    b64 = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    respx.post("https://www.virustotal.com/api/v3/urls").mock(
        return_value=Response(200, json={"data": {"id": "ignored"}})
    )
    respx.get(f"https://www.virustotal.com/api/v3/urls/{b64}").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 1, "suspicious": 2},
                        "last_analysis_results": {
                            "VendorX": {"category": "suspicious"},
                            "VendorY": {"category": "malicious"},
                        },
                    }
                }
            },
        )
    )

    status, detail, vendors = await vt.query_virustotal(url)
    assert status == "suspicious"
    # Detail includes both counts and the configured threshold
    assert "1 malicious" in detail and "2 suspicious" in detail
    assert "threshold 4" in detail
    assert vendors["VendorY"] == "malicious"


@pytest.mark.asyncio
@respx.mock
async def test_query_virustotal_detail_includes_counts(monkeypatch):
    import utils.virustotal as vt
    monkeypatch.setattr(vt, "VT_API_KEY", "dummy-key", raising=False)
    vt._vt_cache.clear()

    # Make malicious threshold high so result is suspicious, not malicious
    monkeypatch.setattr(vt.config, "VT_MALICIOUS_THRESHOLD", 10, raising=False)
    monkeypatch.setattr(vt.config, "VT_SUSPICIOUS_THRESHOLD", 1, raising=False)

    url = "http://example.com/detail"
    b64 = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    respx.post("https://www.virustotal.com/api/v3/urls").mock(
        return_value=Response(200, json={"data": {"id": "ignored"}})
    )
    respx.get(f"https://www.virustotal.com/api/v3/urls/{b64}").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 2, "suspicious": 3},
                        "last_analysis_results": {
                            "A": {"category": "malicious"},
                            "B": {"category": "suspicious"},
                            "C": {"category": "harmless"},
                        },
                    }
                }
            },
        )
    )

    status, detail, _ = await vt.query_virustotal(url)
    assert status == "suspicious"
    assert "2 malicious" in detail and "3 suspicious" in detail


# Tests for routes.scan.scan_urls vendor logging when status is malicious/suspicious

@pytest.mark.asyncio
@pytest.mark.parametrize("vt_status", ["malicious", "suspicious"])
async def test_scan_urls_logs_flagging_vendors(vt_status, caplog, monkeypatch):
    from routes import scan as scan_mod
    from models.scan_models import URLScanRequest

    # Patch DNS and SSL checks to succeed
    monkeypatch.setattr(scan_mod.socket, "gethostbyname", lambda d: "1.2.3.4")
    async def _ok_ssl(_domain):
        return True, []
    monkeypatch.setattr(scan_mod, "async_ssl_check", _ok_ssl)

    # Patch VT result to include vendors (including harmless/undetected which should be filtered out)
    async def fake_query(url: str):
        vendors = {
            "Kaspersky": "suspicious",
            "Symantec": "malicious",
            "CleanMX": "harmless",
            "Unknown": "undetected",
        }
        return vt_status, "test-detail", vendors
    monkeypatch.setattr(scan_mod, "query_virustotal", fake_query)

    caplog.set_level("INFO")

    req = URLScanRequest(urls=["https://example.com/a"])
    results = await scan_mod.scan_urls(req)

    # Assert API response passes vendors through for malicious/suspicious
    assert results[0].status == vt_status
    assert results[0].vendors is not None

    # Assert that a log line with flagged vendors (excluding harmless/undetected) was emitted
    matched = [m for m in caplog.messages if m.startswith("Vendors flagged:")]
    assert matched, "Expected vendors flagged log entry"
    msg = matched[-1]
    assert "Symantec:malicious" in msg and "Kaspersky:suspicious" in msg
    assert "CleanMX" not in msg and "Unknown" not in msg


# Config thresholds load from environment variables

def test_config_thresholds_loaded_from_env():
    import config as config_mod
    # Save originals
    orig_mal = os.environ.get("VT_MALICIOUS_THRESHOLD")
    orig_susp = os.environ.get("VT_SUSPICIOUS_THRESHOLD")
    try:
        os.environ["VT_MALICIOUS_THRESHOLD"] = "7"
        os.environ["VT_SUSPICIOUS_THRESHOLD"] = "2"
        # Reload module to re-evaluate class attributes from env
        importlib.reload(config_mod)
        assert config_mod.config.VT_MALICIOUS_THRESHOLD == 7
        assert config_mod.config.VT_SUSPICIOUS_THRESHOLD == 2
    finally:
        # Restore env and reload again to avoid polluting other tests
        if orig_mal is None:
            os.environ.pop("VT_MALICIOUS_THRESHOLD", None)
        else:
            os.environ["VT_MALICIOUS_THRESHOLD"] = orig_mal
        if orig_susp is None:
            os.environ.pop("VT_SUSPICIOUS_THRESHOLD", None)
        else:
            os.environ["VT_SUSPICIOUS_THRESHOLD"] = orig_susp
        importlib.reload(config_mod)
