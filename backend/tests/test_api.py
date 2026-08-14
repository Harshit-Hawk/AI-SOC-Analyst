import pytest
import httpx
from app.main import app

@pytest.mark.anyio
async def test_health_check():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "ai_mode" in data

@pytest.mark.anyio
async def test_ingest_json_events():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "format": "json",
            "raw_data": [
                {
                    "source_ip": "192.168.1.55",
                    "destination_ip": "10.0.0.1",
                    "destination_port": 80,
                    "protocol": "TCP",
                    "event_type": "network",
                    "username": "admin",
                    "action": "login",
                    "status": "failure",
                    "message": "Auth failed"
                }
            ]
        }
        response = await client.post("/api/v1/events/ingest", json=payload)
        assert response.status_code == 200
        assert response.json()["normalized_count"] == 1

@pytest.mark.anyio
async def test_simulator_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/simulator/run?scenario=brute_force")
        assert response.status_code == 200
        data = response.json()
        assert data["events_generated"] > 0
        assert "new_incidents" in data

@pytest.mark.anyio
async def test_benchmark_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/benchmark/evaluate")
        assert response.status_code == 200
        data = response.json()
        assert "Rule-Based" in data
        assert "ML-Based" in data
        assert "Hybrid" in data
        assert data["Hybrid"]["precision"] >= 0.0
