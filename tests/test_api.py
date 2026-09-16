import pytest

@pytest.mark.asyncio
async def test_health_endpoint(client):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["version"] == "1.0.0"

@pytest.mark.asyncio
async def test_check_url_endpoint(client):
    payload = {"url": "https://www.google.com"}
    response = await client.post("/api/v1/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "verdict" in data
    assert "risk_score" in data
    assert data["verdict"] in ["Safe", "Suspicious", "Phishing"]

@pytest.mark.asyncio
async def test_stats_endpoint(client):
    response = await client.get("/api/v1/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "phishing_detected" in data
