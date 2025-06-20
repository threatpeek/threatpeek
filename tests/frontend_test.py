import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app

from fastapi.testclient import TestClient


client = TestClient(app)

def test_dashboard_loads():
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "<html" in response.text.lower()
