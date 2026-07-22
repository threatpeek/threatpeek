from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_export_csv_defangs_urls(monkeypatch):
    from routes import scan as scan_mod

    monkeypatch.setattr(scan_mod.socket, "gethostbyname", lambda _domain: "1.2.3.4")

    async def _ok_ssl(_domain):
        return True, []

    async def _clean_vt(_url: str):
        return "clean", "No threats found by VirusTotal.", {}

    monkeypatch.setattr(scan_mod, "async_ssl_check", _ok_ssl)
    monkeypatch.setattr(scan_mod, "query_virustotal", _clean_vt)

    response = client.post(
        "/api/export/csv",
        json={"urls": ["https://www.google.com/path.a"]},
    )

    assert response.status_code == 200
    body = response.text
    assert "https://www[.]google[.]com/path[.]a" in body
    assert "https://www.google.com/path.a" not in body
