"""Caché en SQLite con expiración. Evita repetir consultas y gastar cuota de las APIs."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path


class Cache:
    def __init__(self, path: Path | None, enabled: bool = True) -> None:
        self.enabled = enabled and path is not None
        self._db: sqlite3.Connection | None = None
        if self.enabled:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(path)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS responses ("
                "key TEXT PRIMARY KEY, expires REAL NOT NULL, payload TEXT NOT NULL)"
            )
            self._db.commit()

    @staticmethod
    def make_key(method: str, url: str, params: dict | None) -> str:
        raw = json.dumps([method.upper(), url, sorted((params or {}).items())])
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, key: str) -> dict | None:
        if not self._db:
            return None
        row = self._db.execute(
            "SELECT payload, expires FROM responses WHERE key = ?", (key,)
        ).fetchone()
        if not row:
            return None
        payload, expires = row
        if expires < time.time():
            self._db.execute("DELETE FROM responses WHERE key = ?", (key,))
            self._db.commit()
            return None
        return json.loads(payload)

    def set(self, key: str, payload: dict, ttl: float) -> None:
        if not self._db:
            return
        self._db.execute(
            "INSERT OR REPLACE INTO responses VALUES (?, ?, ?)",
            (key, time.time() + ttl, json.dumps(payload)),
        )
        self._db.commit()

    def purge(self) -> int:
        if not self._db:
            return 0
        cur = self._db.execute("DELETE FROM responses WHERE expires < ?", (time.time(),))
        self._db.commit()
        return cur.rowcount

    def close(self) -> None:
        if self._db:
            self._db.close()
            self._db = None
