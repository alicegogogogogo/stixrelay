from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS collections (
              id TEXT PRIMARY KEY,
              document TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS objects (
              collection_id TEXT NOT NULL REFERENCES collections(id),
              object_id TEXT NOT NULL,
              version TEXT NOT NULL,
              type TEXT NOT NULL,
              added_at TEXT NOT NULL,
              document TEXT NOT NULL,
              PRIMARY KEY (collection_id, object_id, version)
            );
            CREATE INDEX IF NOT EXISTS objects_delta
              ON objects(collection_id, added_at, object_id);
            CREATE TABLE IF NOT EXISTS idempotency (
              key TEXT PRIMARY KEY,
              operation TEXT NOT NULL,
              response TEXT NOT NULL,
              status INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              collection_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              limit_value INTEGER NOT NULL,
              type_filter TEXT
            );
            CREATE TABLE IF NOT EXISTS snapshot_entries (
              snapshot_id INTEGER NOT NULL,
              position INTEGER NOT NULL,
              document TEXT NOT NULL,
              PRIMARY KEY (snapshot_id, position)
            );
            CREATE TABLE IF NOT EXISTS meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            """
        )
        self.cursor_secret = self._load_secret()

    def _load_secret(self) -> bytes:
        """Return the persistent secret used to sign page cursors."""
        row = self.connection.execute(
            "SELECT value FROM meta WHERE key = 'cursor_secret'"
        ).fetchone()
        if row is not None:
            return bytes.fromhex(row["value"])
        secret = os.urandom(32)
        self.connection.execute(
            "INSERT INTO meta(key, value) VALUES ('cursor_secret', ?)",
            (secret.hex(),),
        )
        return secret

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self.connection
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        else:
            self.connection.execute("COMMIT")

    @staticmethod
    def encode(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def decode(value: str) -> Any:
        return json.loads(value)

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
