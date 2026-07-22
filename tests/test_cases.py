from fastapi.testclient import TestClient

from main import app
from storage import case_store


def test_cases_can_be_saved_opened_and_annotated(monkeypatch, tmp_path):
    monkeypatch.setattr(case_store.config, "CASE_DATABASE_PATH", str(tmp_path / "cases.db"))
    client = TestClient(app)
    payload = {
        "title": "Credential phishing review",
        "tags": ["phishing", "priority"],
        "note": "Initial review requested by support.",
        "results": [{
            "url": "https://example.test/login",
            "status": "suspicious",
            "details": "VT detections: 1 suspicious.",
            "risk_score": 55,
            "risk_factors": ["1 VirusTotal vendor marked it suspicious"],
            "redirect_chain": [{"url": "https://example.test/login", "status_code": 200}],
        }],
    }

    saved = client.post("/api/cases", json=payload)
    assert saved.status_code == 201
    case = saved.json()
    assert case["title"] == payload["title"]
    assert case["result_count"] == 1
    assert case["notes"][0]["body"] == payload["note"]

    listed = client.get("/api/cases")
    assert listed.status_code == 200
    assert listed.json()[0]["id"] == case["id"]

    noted = client.post(f"/api/cases/{case['id']}/notes", json={"body": "Confirmed for escalation."})
    assert noted.status_code == 200
    assert [note["body"] for note in noted.json()["notes"]] == [
        "Initial review requested by support.",
        "Confirmed for escalation.",
    ]
