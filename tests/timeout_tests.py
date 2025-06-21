import pytest
from main import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_slow_site_timeout():
    response = client.post("/api/scan_url", json={"url": "http://10.255.255.1"})  # unroutable IP
    assert response.status_code == 200
    assert "suspicious" in response.json()["status"]
