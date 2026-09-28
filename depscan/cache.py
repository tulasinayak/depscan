"""SQLite cache for raw API responses: key -> (JSON, fetched_at)."""

import json
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any


class ResponseCache:
    def __init__(self, path: Path, ttl_seconds: float, clock: Callable[[], float] = time.time):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl_seconds
        self.clock = clock
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS responses ("
                         "key TEXT PRIMARY KEY, data TEXT NOT NULL, fetched_at REAL NOT NULL)")
        self._db.commit()

    def get(self, key: str) -> tuple[Any, float] | None:
        """(data, fetched_at) or None. Returns expired entries too; check with is_fresh()."""
        with self._lock:
            row = self._db.execute("SELECT data, fetched_at FROM responses WHERE key = ?", (key,)).fetchone()
        return (json.loads(row[0]), row[1]) if row else None

    def put(self, key: str, data: Any) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO responses (key, data, fetched_at) VALUES (?, ?, ?)",
                             (key, json.dumps(data), self.clock()))
            self._db.commit()

    def is_fresh(self, fetched_at: float) -> bool:
        return self.clock() - fetched_at < self.ttl

    def close(self) -> None:
        with self._lock:
            self._db.close()
