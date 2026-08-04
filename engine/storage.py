"""
SQLite-backed results store.
Every scan run and every individual payload result is persisted here,
enabling trend analysis across runs.
"""
import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


DB_PATH = Path("./reports/results.db")


@dataclass
class PayloadResult:
    run_id: str
    payload_id: str
    category: str
    technique: str
    severity: str
    prompt: str
    response: str
    verdict: str        # COMPLIED | REFUSED | PARTIAL_LEAK | ERROR
    justification: str
    score: float        # 0.0 (attack succeeded) → 1.0 (model refused)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


class ResultsStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    id          TEXT PRIMARY KEY,
                    timestamp   TEXT NOT NULL,
                    config      TEXT,
                    target_type TEXT,
                    model       TEXT,
                    suites      TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS results (
                    id            TEXT PRIMARY KEY,
                    run_id        TEXT NOT NULL,
                    payload_id    TEXT,
                    category      TEXT,
                    technique     TEXT,
                    severity      TEXT,
                    prompt        TEXT,
                    response      TEXT,
                    verdict       TEXT,
                    justification TEXT,
                    score         REAL,
                    timestamp     TEXT,
                    FOREIGN KEY (run_id) REFERENCES runs(id)
                )
            """)
            conn.commit()

    def create_run(self, run_id: str, config: dict) -> str:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    datetime.utcnow().isoformat(),
                    json.dumps(config),
                    config.get("target", {}).get("type", "unknown"),
                    config.get("target", {}).get("model", "unknown"),
                    json.dumps(config.get("suites", [])),
                ),
            )
            conn.commit()
        return run_id

    def save_result(self, result: PayloadResult):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    result.id,
                    result.run_id,
                    result.payload_id,
                    result.category,
                    result.technique,
                    result.severity,
                    result.prompt,
                    result.response,
                    result.verdict,
                    result.justification,
                    result.score,
                    result.timestamp,
                ),
            )
            conn.commit()

    def get_run_results(self, run_id: str) -> list[PayloadResult]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM results WHERE run_id = ? ORDER BY timestamp",
                (run_id,),
            ).fetchall()
        return [PayloadResult(**dict(r)) for r in rows]

    def list_runs(self) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, timestamp, target_type, model, suites "
                "FROM runs ORDER BY timestamp DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_run_summary(self, run_id: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
        return dict(row) if row else None
