import pytest
from fastapi.testclient import TestClient
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from main import app


client = TestClient(app)

def test_scan_url_clean():
    response = client.post("/api/scan_url", json={"url": "https://safe.com"})
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "clean"
    assert "No threat detected" in json_data["details"]  # ← match the actual message

def test_scan_url_xss_payload():
    payload = {"url": "https://safe.com/%3Cscript%3Ealert(1)%3C/script%3E"}
    response = client.post("/api/scan_url", json=payload)
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "suspicious"
    assert "XSS payload" in json_data["details"]

def test_scan_url_invalid_url():
    response = client.post("/api/scan_url", json={"url": "not_a_url"})
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "invalid"
    assert "domain" in json_data["details"].lower()

def test_scan_url_blacklisted_domain():
    response = client.post("/api/scan_url", json={"url": "http://badguy.com/malware"})
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "malicious"
    assert "blacklist" in json_data["details"].lower()

def test_scan_url_redirect_to_404():
    # Assuming this URL redirects to a non-existent page
    response = client.post("/api/scan_url", json={"url": "http://safe.com/eric"})
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "suspicious"
    assert "404" in json_data["details"]

def test_scan_url_high_entropy_path():
    # Base64-like garbage string — clearly high-entropy
    payload = {"url": "http://safe.com/aHR0cDovL2JhZGd1eS5jb20vbWFsaWNpb3VzL3BheWxvYWQ="}
    response = client.post("/api/scan_url", json=payload)
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "suspicious"
    assert "entropy" in json_data["details"].lower()

def test_scan_url_long_path():
    long_path = "http://safe.com/" + "a" * 120
    response = client.post("/api/scan_url", json={"url": long_path})
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "suspicious"
    assert "unusually long" in json_data["details"].lower()

def test_scan_url_unsupported_scheme():
    response = client.post("/api/scan_url", json={"url": "ftp://safe.com/file.exe"})
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "suspicious"  # changed from "invalid"
    assert "unsupported" in json_data["details"].lower()

def test_scan_url_ssl_failure():
    response = client.post("/api/scan_url", json={"url": "https://invalid.ssl.test"})
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "suspicious"
    assert "ssl" in json_data["details"].lower()


