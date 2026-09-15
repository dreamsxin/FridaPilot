"""FridaPilot Storage - SQLite persistence layer.

Stores task history, scripts, hook points, execution results,
and collected messages for replay and knowledge reuse.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generator


DEFAULT_DB_PATH = Path.home() / ".fridapilot" / "history.db"

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    device TEXT NOT NULL DEFAULT 'local',
    plan_json TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL,
    finished_at REAL,
    report TEXT
);

CREATE TABLE IF NOT EXISTS steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    step_index INTEGER NOT NULL,
    tool TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    args_json TEXT,
    success INTEGER,
    result_json TEXT,
    error TEXT,
    duration REAL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER REFERENCES tasks(id),
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS hook_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT '',
    class_name TEXT NOT NULL DEFAULT '',
    method_name TEXT NOT NULL DEFAULT '',
    module_name TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    discovered_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER REFERENCES tasks(id),
    step_id INTEGER REFERENCES steps(id),
    msg_type TEXT NOT NULL,
    payload_json TEXT,
    timestamp REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tasks_target ON tasks(target);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_scripts_target ON scripts(target);
CREATE INDEX IF NOT EXISTS idx_scripts_tags ON scripts(tags);
CREATE INDEX IF NOT EXISTS idx_hook_points_target ON hook_points(target);
CREATE INDEX IF NOT EXISTS idx_messages_task ON messages(task_id);

CREATE TABLE IF NOT EXISTS analysis_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash TEXT NOT NULL UNIQUE,
    filepath TEXT NOT NULL,
    analysis_type TEXT NOT NULL,
    result_json TEXT NOT NULL,
    file_size INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_analysis_cache_hash ON analysis_cache(file_hash);
"""


class Database:
    """SQLite database for FridaPilot history and knowledge."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ── Tasks ─────────────────────────────────────────────

    def create_task(self, goal: str, target: str = "", device: str = "local",
                    plan_json: str = "") -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO tasks (goal, target, device, plan_json, status, created_at) VALUES (?,?,?,?,?,?)",
                (goal, target, device, plan_json, "running", time.time()),
            )
            return cur.lastrowid

    def finish_task(self, task_id: int, status: str = "completed", report: str = "") -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE tasks SET status=?, finished_at=?, report=? WHERE id=?",
                (status, time.time(), report, task_id),
            )

    def get_task(self, task_id: int) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            return dict(row) if row else None

    def list_tasks(self, target: str = "", limit: int = 20) -> list[dict]:
        with self._conn() as conn:
            if target:
                rows = conn.execute(
                    "SELECT * FROM tasks WHERE target=? ORDER BY created_at DESC LIMIT ?",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,),
                ).fetchall()
            return [dict(r) for r in rows]

    # ── Steps ─────────────────────────────────────────────

    def save_step(self, task_id: int, step_index: int, tool: str,
                  description: str = "", args: dict | None = None,
                  success: bool | None = None, result: Any = None,
                  error: str = "", duration: float = 0.0) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO steps (task_id, step_index, tool, description, args_json, success, result_json, error, duration, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (task_id, step_index, tool, description,
                 json.dumps(args, default=str) if args else None,
                 int(success) if success is not None else None,
                 json.dumps(result, default=str) if result is not None else None,
                 error, duration, time.time()),
            )
            return cur.lastrowid

    # ── Scripts ───────────────────────────────────────────

    def save_script(self, name: str, source: str, target: str = "",
                    platform: str = "", tags: str = "", task_id: int | None = None) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scripts (task_id, name, source, target, platform, tags, created_at) VALUES (?,?,?,?,?,?,?)",
                (task_id, name, source, target, platform, tags, time.time()),
            )
            return cur.lastrowid

    def find_scripts(self, target: str = "", platform: str = "",
                     tags: str = "", limit: int = 10) -> list[dict]:
        with self._conn() as conn:
            query = "SELECT * FROM scripts WHERE 1=1"
            params: list = []
            if target:
                query += " AND target=?"
                params.append(target)
            if platform:
                query += " AND platform=?"
                params.append(platform)
            if tags:
                query += " AND tags LIKE ?"
                params.append(f"%{tags}%")
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    # ── Hook Points ───────────────────────────────────────

    def save_hook_point(self, target: str, platform: str = "",
                        class_name: str = "", method_name: str = "",
                        module_name: str = "", address: str = "",
                        description: str = "") -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO hook_points (target, platform, class_name, method_name, module_name, address, description, discovered_at) VALUES (?,?,?,?,?,?,?,?)",
                (target, platform, class_name, method_name, module_name, address, description, time.time()),
            )
            return cur.lastrowid

    def find_hook_points(self, target: str, limit: int = 50) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM hook_points WHERE target=? ORDER BY discovered_at DESC LIMIT ?",
                (target, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Messages ──────────────────────────────────────────

    def save_messages(self, task_id: int, messages: list[dict],
                      step_id: int | None = None) -> None:
        with self._conn() as conn:
            for msg in messages:
                conn.execute(
                    "INSERT INTO messages (task_id, step_id, msg_type, payload_json, timestamp) VALUES (?,?,?,?,?)",
                    (task_id, step_id, msg.get("type", "unknown"),
                     json.dumps(msg.get("payload"), default=str),
                     msg.get("timestamp", time.time())),
                )

    def get_messages(self, task_id: int, limit: int = 500) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM messages WHERE task_id=? ORDER BY timestamp LIMIT ?",
                (task_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Analysis Cache ────────────────────────────────────

    def get_cached_analysis(self, file_hash: str, analysis_type: str) -> dict | None:
        """Look up a cached binary analysis result by file hash and type.

        Args:
            file_hash: SHA-256 hash of the binary file.
            analysis_type: Type of analysis (e.g. "pe", "elf", "go", "crypto").

        Returns:
            Cached result dict or None if not found.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM analysis_cache WHERE file_hash=? AND analysis_type=?",
                (file_hash, analysis_type),
            ).fetchone()
            if row:
                result = dict(row)
                result["result"] = json.loads(result["result_json"])
                return result
            return None

    def save_analysis_cache(
        self, file_hash: str, filepath: str, analysis_type: str,
        result: dict, file_size: int = 0,
    ) -> None:
        """Cache a binary analysis result.

        Args:
            file_hash: SHA-256 hash of the binary file.
            filepath: Original file path (for display).
            analysis_type: Type of analysis.
            result: Analysis result dict to cache.
            file_size: Size of the analyzed file in bytes.
        """
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO analysis_cache "
                "(file_hash, filepath, analysis_type, result_json, file_size, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (file_hash, filepath, analysis_type,
                 json.dumps(result, default=str), file_size, time.time()),
            )

    def clear_analysis_cache(self, older_than_days: int = 30) -> int:
        """Remove stale cache entries.

        Args:
            older_than_days: Remove entries older than this many days.

        Returns:
            Number of entries removed.
        """
        cutoff = time.time() - (older_than_days * 86400)
        with self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM analysis_cache WHERE created_at < ?", (cutoff,),
            )
            return cur.rowcount
