import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as db:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, scenario TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, data TEXT NOT NULL
              );
              CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
                time TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL
              );
              CREATE INDEX IF NOT EXISTS events_run ON events(run_id, id);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self, run_id, scenario, models):
        from .config import REQUIRED_TESTS
        policy = ({"version": 0, "mode": "observe", "scope": "test_integrity", "require_full_suite": False,
                   "required_tests": list(REQUIRED_TESTS)} if scenario == "test-laundering"
                  else {"version": 0, "mode": "observe", "file_mode": "0644"})
        with self.connect() as db:
            db.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?)", (
                run_id, scenario, "queued", now(), json.dumps({
                    "models": models, "policy": policy,
                    "verification": {}, "sandbox_id": None, "cleanup": "pending", "live": True,
                }),
            ))

    def get(self, run_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            return None
        return {"id": row["id"], "scenario": row["scenario"], "status": row["status"],
                "created_at": row["created_at"], **json.loads(row["data"])}

    def list(self):
        with self.connect() as db:
            ids = [r[0] for r in db.execute("SELECT id FROM runs ORDER BY created_at DESC LIMIT 30")]
        return [self.get(run_id) for run_id in ids]

    def recovery_candidates(self):
        from .models import TERMINAL
        placeholders = ",".join("?" for _ in TERMINAL)
        with self.connect() as db:
            ids = [r[0] for r in db.execute(
                f"SELECT id FROM runs WHERE status NOT IN ({placeholders}) OR json_extract(data, '$.cleanup') IN ('failed', 'check_labels')",
                tuple(TERMINAL),
            )]
        return [self.get(run_id) for run_id in ids]

    def update(self, run_id, status=None, **fields):
        with self.connect() as db:
            row = db.execute("SELECT status, data FROM runs WHERE id=?", (run_id,)).fetchone()
            data = {**json.loads(row["data"]), **fields}
            db.execute("UPDATE runs SET status=?, data=? WHERE id=?",
                       (status or row["status"], json.dumps(data, ensure_ascii=False), run_id))

    def event(self, run_id, kind, **data):
        with self.connect() as db:
            cursor = db.execute("INSERT INTO events(run_id,time,kind,data) VALUES (?,?,?,?)",
                                (run_id, now(), kind, json.dumps(data, ensure_ascii=False)))
            return cursor.lastrowid

    def events(self, run_id, after=0):
        with self.connect() as db:
            rows = db.execute("SELECT * FROM events WHERE run_id=? AND id>? ORDER BY id", (run_id, after)).fetchall()
        return [{"id": r["id"], "time": r["time"], "kind": r["kind"], "data": json.loads(r["data"])} for r in rows]
