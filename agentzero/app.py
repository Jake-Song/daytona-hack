import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import Settings, README_FILES
from .engine import RunFailure, RunManager
from .inference import InferenceError
from .models import RunRequest, TERMINAL
from .sandbox import FIXTURES
from .store import Store


def create_app(settings=None, manager_factory=RunManager):
    settings = settings or Settings.from_env()
    store = Store(settings.data_dir / "agentzero.sqlite3")
    manager = manager_factory(settings, store)

    @asynccontextmanager
    async def lifespan(app):
        await manager.recover()
        yield
        await manager.shutdown()

    app = FastAPI(title="AgentZero", lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"])
    app.state.manager = manager
    app.state.store = store

    @app.middleware("http")
    async def local_origin(request, call_next):
        origin = request.headers.get("origin")
        if request.method not in {"GET", "HEAD", "OPTIONS"} and origin and origin not in {
            "http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8000", "http://127.0.0.1:8000",
        }:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Local control API does not accept this browser origin"}, status_code=403)
        return await call_next(request)

    @app.get("/api/health")
    def health():
        return {"configured": not settings.missing(), "missing": settings.missing(),
                "models": {"worker": settings.worker_model, "security": settings.security_model},
                "active_id": manager.active_id if manager.task and not manager.task.done() else None,
                "mode": "live", "same_model": bool(settings.worker_model and settings.worker_model == settings.security_model)}

    @app.get("/api/scenarios")
    def scenarios():
        return {scenario: (FIXTURES / filename).read_text() for scenario, filename in README_FILES.items()}

    @app.post("/api/preflight")
    async def preflight():
        try:
            return await manager.inference.preflight()
        except InferenceError as exc:
            raise HTTPException(503, str(exc)) from None

    @app.get("/api/runs")
    def runs():
        return store.list()

    @app.post("/api/runs", status_code=202)
    async def start(body: RunRequest):
        try:
            run_id = manager.start(body.scenario)
        except InferenceError as exc:
            raise HTTPException(503, str(exc)) from None
        except RunFailure as exc:
            raise HTTPException(409, str(exc)) from None
        return store.get(run_id)

    def existing(run_id):
        run = store.get(run_id)
        if not run:
            raise HTTPException(404, "Run not found")
        return run

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str):
        return {**existing(run_id), "events": store.events(run_id)}

    @app.post("/api/runs/{run_id}/cancel", status_code=202)
    async def cancel(run_id: str):
        existing(run_id)
        manager.cancel(run_id)
        return {"accepted": True}

    @app.get("/api/runs/{run_id}/events")
    async def events(run_id: str, request: Request, after: int = 0):
        existing(run_id)
        try:
            cursor = max(after, int(request.headers.get("last-event-id", "0")))
        except ValueError:
            raise HTTPException(400, "Invalid event cursor") from None

        async def stream():
            nonlocal cursor
            heartbeat = 0
            while not await request.is_disconnected():
                for event in store.events(run_id, cursor):
                    cursor = event["id"]
                    yield f"id: {cursor}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
                if store.get(run_id)["status"] in TERMINAL:
                    break
                heartbeat += 1
                if heartbeat % 20 == 0:
                    yield ": heartbeat\n\n"
                await asyncio.sleep(0.5)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=dist, html=True), name="dashboard")
    return app
