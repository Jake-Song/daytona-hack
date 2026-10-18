from fastapi.testclient import TestClient

from agentzero.app import create_app
from agentzero.config import Settings
from agentzero.engine import RunManager
from conftest import FixtureInference, FixtureSandbox


def test_missing_configuration_is_explicit_and_no_fake_run_created(tmp_path):
    app = create_app(Settings(data_dir=tmp_path))
    with TestClient(app, base_url="http://localhost") as client:
        health = client.get("/api/health").json()
        assert health["mode"] == "live" and not health["configured"]
        assert "NOSANA_API_KEY" in health["missing"]
        assert client.post("/api/runs", json={"scenario": "readme-injection"}).status_code == 503
        assert client.get("/api/runs").json() == []


def test_api_sse_cursor_and_browser_origin(system):
    def manager_factory(settings, store):
        return RunManager(settings, store, inference=FixtureInference(), sandbox_factory=FixtureSandbox)
    app = create_app(system[0], manager_factory)
    with TestClient(app, base_url="http://localhost") as client:
        assert client.post("/api/runs", json={"scenario": "bad"}).status_code == 422
        assert client.post("/api/runs", json={}, headers={"Origin": "https://attacker.example"}).status_code == 403
        assert client.get("/api/runs/not-found").status_code == 404
        assert client.get("/api/health", headers={"Host": "attacker.example"}).status_code == 400
        # Execute the run on the app's own event loop and wait without polling.
        response = client.post("/api/runs", json={"scenario": "readme-injection"})
        assert response.status_code == 202
        run_id = response.json()["id"]
        async def wait():
            await app.state.manager.task
        client.portal.call(wait)
        snapshot = client.get(f"/api/runs/{run_id}").json()
        assert snapshot["status"] == "succeeded"
        cursor = snapshot["events"][-3]["id"]
        stream = client.get(f"/api/runs/{run_id}/events", headers={"Last-Event-ID": str(cursor)})
        assert stream.status_code == 200
        assert stream.headers["content-type"].startswith("text/event-stream")
        assert stream.text.count("data: ") == 2
        assert '"kind": "completed"' in stream.text
        assert client.get(f"/api/runs/{run_id}/events", headers={"Last-Event-ID": "bad"}).status_code == 400
