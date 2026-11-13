"""
storage.py -- Lightweight SQLite persistence.

Used to remember which client_ids and tunnels have existed, so the
dashboard can show history and so the server can recognise reconnecting
clients. Correctness of live routing does NOT depend on this database --
that is held in memory and rebuilt as clients (re)connect and (re)request
their tunnels. This file exists purely for bookkeeping / observability and
so the server can "recover cleanly" (i.e. never crash / never serve stale
routes) after a restart, per the design goals.

All access happens from the server's single asyncio event loop (the calls
are small and infrequent -- connect/open-tunnel/close-tunnel events, never
per-packet), so no locking is needed. The database runs in WAL mode with a
bounded busy timeout and synchronous=NORMAL: durable enough for
bookkeeping, but without an fsync on every statement.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Optional


class Storage:
    def __init__(self, db_path: str, busy_timeout_ms: int = 100):
        self.db_path = db_path
        self._closed = False
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=busy_timeout_ms / 1000.0)
        self._conn.row_factory = sqlite3.Row
        self._init_schema(busy_timeout_ms)

    def _init_schema(self, busy_timeout_ms: int):
        with self._conn:
            # WAL keeps readers (the dashboard's periodic purge) from blocking
            # the writer, and NORMAL avoids an fsync per bookkeeping write.
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass  # e.g. :memory: or a filesystem without WAL support
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS clients (
                    client_id   TEXT PRIMARY KEY,
                    first_seen  REAL NOT NULL,
                    last_seen   REAL NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tunnels (
                    tunnel_id    TEXT PRIMARY KEY,
                    client_id    TEXT NOT NULL,
                    type         TEXT NOT NULL,
                    subdomain    TEXT,
                    remote_port  INTEGER,
                    created_at   REAL NOT NULL,
                    last_seen    REAL NOT NULL
                )
                """
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tunnels_client ON tunnels(client_id)")

    # -- clients --------------------------------------------------------

    def upsert_client(self, client_id: str):
        now = time.time()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO clients(client_id, first_seen, last_seen) VALUES (?, ?, ?)
                ON CONFLICT(client_id) DO UPDATE SET last_seen=excluded.last_seen
                """,
                (client_id, now, now),
            )

    def touch_client(self, client_id: str):
        with self._conn:
            self._conn.execute("UPDATE clients SET last_seen=? WHERE client_id=?", (time.time(), client_id))

    # -- tunnels ----------------------------------------------------------

    def save_tunnel(self, tunnel_id: str, client_id: str, ttype: str,
                     subdomain: Optional[str], remote_port: Optional[int]):
        now = time.time()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO tunnels(tunnel_id, client_id, type, subdomain, remote_port, created_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tunnel_id) DO UPDATE SET
                    client_id=excluded.client_id,
                    subdomain=excluded.subdomain,
                    remote_port=excluded.remote_port,
                    last_seen=excluded.last_seen
                """,
                (tunnel_id, client_id, ttype, subdomain, remote_port, now, now),
            )

    def touch_tunnel(self, tunnel_id: str):
        with self._conn:
            self._conn.execute("UPDATE tunnels SET last_seen=? WHERE tunnel_id=?", (time.time(), tunnel_id))

    def touch_tunnels_for_client(self, client_id: str):
        """Refresh last_seen for every tunnel still owned by a live client."""
        with self._conn:
            self._conn.execute("UPDATE tunnels SET last_seen=? WHERE client_id=?", (time.time(), client_id))

    def delete_tunnel(self, tunnel_id: str):
        with self._conn:
            self._conn.execute("DELETE FROM tunnels WHERE tunnel_id=?", (tunnel_id,))

    def delete_tunnels_for_client(self, client_id: str):
        with self._conn:
            self._conn.execute("DELETE FROM tunnels WHERE client_id=?", (client_id,))

    def purge_stale(self, max_age_seconds: float):
        """Remove bookkeeping rows that haven't been touched in a long time.

        This is what makes previously-used subdomains/ports eventually
        available for reuse by other clients if the original owner never
        comes back. Active records are periodically touched, so only truly
        abandoned history is purged.
        """
        cutoff = time.time() - max_age_seconds
        with self._conn:
            self._conn.execute("DELETE FROM tunnels WHERE last_seen < ?", (cutoff,))
            self._conn.execute("DELETE FROM clients WHERE last_seen < ?", (cutoff,))

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._conn.close()
