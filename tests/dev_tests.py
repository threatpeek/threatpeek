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
    assert "No known threat indicators" in json_data["details"]

def test_scan_url_xss_payload():
    payload = {"url": "https://safe.com/%3Cscript%3Ealert(1)%3C/script%3E"}
    response = client.post("/api/scan_url", json=payload)
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "suspicious"
    assert "XSS payload" in json_data["details"]

def test_scan_url_invalid_url():
    # Missing scheme should fail validation and return 422
    response = client.post("/api/scan_url", json={"url": "not_a_url"})
    assert response.status_code == 422
