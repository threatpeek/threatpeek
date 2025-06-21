import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_empty_url():
    response = client.post("/api/scan_url", json={"url": ""})
    assert response.status_code == 200
    assert "invalid" in response.json()["status"]

def test_whitespace_url():
    response = client.post("/api/scan_url", json={"url": "   "})
    assert response.status_code == 200
    assert "invalid" in response.json()["status"]

def test_single_char_domain():
    response = client.post("/api/scan_url", json={"url": "http://x"})
    assert response.status_code == 200
    assert response.json()["status"] in ["invalid", "suspicious"]
