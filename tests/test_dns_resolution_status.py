import os
import sys
import socket
import pytest

# Ensure project root on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _make_client():
    from main import app
    from fastapi.testclient import TestClient
    return TestClient(app)


def test_scan_url_singular_dns_unresolvable_returns_invalid(monkeypatch):
    # Patch DNS resolution to raise for this test
    from routes import scan as scan_mod
    monkeypatch.setattr(scan_mod.socket, "gethostbyname", lambda d: (_ for _ in ()).throw(socket.gaierror("NXDOMAIN")))

    client = _make_client()
    resp = client.post("/api/scan_url", json={"url": "nonexistent-domain.example"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "invalid"
    assert "dns" in body["details"].lower()


def test_scan_urls_plural_dns_unresolvable_returns_invalid(monkeypatch):
    from routes import scan as scan_mod
    monkeypatch.setattr(scan_mod.socket, "gethostbyname", lambda d: (_ for _ in ()).throw(socket.gaierror("NXDOMAIN")))

    client = _make_client()
    resp = client.post("/api/scan_urls", json={"urls": ["nonexistent-domain.example"]})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list) and data
    assert data[0]["status"] == "invalid"
    assert "dns" in data[0]["details"].lower()
