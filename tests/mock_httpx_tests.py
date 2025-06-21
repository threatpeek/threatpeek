import pytest
import respx
from httpx import Response
from main import app
from fastapi.testclient import TestClient

client = TestClient(app)

@respx.mock
def test_mock_redirect_chain():
    url = "http://mockedsite.com"
    respx.get(url).mock(
        return_value=Response(200, headers={"Location": "http://final.com"}, text="OK")
    )
    response = client.post("/api/scan_url", json={"url": url})
    assert response.status_code == 200
    assert "clean" in response.json()["status"]
