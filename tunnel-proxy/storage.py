"""
storage.py -- Lightweight SQLite persistence.

Used to remember which client_ids and tunnels have existed, so the
dashboard can show history and so the server can recognise reconnecting
clients. Correctness of live routing does NOT depend on this database --
that is held in memory and rebuilt as clients (re)connect and (re)request
their tunnels. This file exists purely for bookkeeping / observability and
so the server can "recover cleanly" (i.e. never crash / never serve stale
routes) after a restart, per the design goals.

sqlite3 is used synchronously. All operations here are small, local,
infrequent (connect/open-tunnel/close-tunnel events, not per-request), so
a plain threading.Lock is sufficient and keeps this module dependency-free.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from typing import Optional


class Storage:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        with self._lock, self._conn:
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
        with self._lock, self._conn:
            # Portable upsert: INSERT OR IGNORE keeps first_seen; the UPDATE
            # refreshes last_seen. (ON CONFLICT ... DO UPDATE requires a
            # newer SQLite than some Python 3.7 builds ship.)
            self._conn.execute(
                "INSERT OR IGNORE INTO clients(client_id, first_seen, last_seen) "
                "VALUES (?, ?, ?)",
                (client_id, now, now),
            )
            self._conn.execute(
                "UPDATE clients SET last_seen=? WHERE client_id=?",
                (now, client_id),
            )

    def touch_client(self, client_id: str):
        with self._lock, self._conn:
            self._conn.execute("UPDATE clients SET last_seen=? WHERE client_id=?", (time.time(), client_id))

    # -- tunnels ----------------------------------------------------------

    def save_tunnel(self, tunnel_id: str, client_id: str, ttype: str,
                     subdomain: Optional[str], remote_port: Optional[int]):
        now = time.time()
        with self._lock, self._conn:
            # Portable upsert preserving created_at on re-registration.
            self._conn.execute(
                "INSERT OR IGNORE INTO tunnels(tunnel_id, client_id, type, subdomain, "
                "remote_port, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tunnel_id, client_id, ttype, subdomain, remote_port, now, now),
            )
            self._conn.execute(
                "UPDATE tunnels SET client_id=?, type=?, subdomain=?, remote_port=?, "
                "last_seen=? WHERE tunnel_id=?",
                (client_id, ttype, subdomain, remote_port, now, tunnel_id),
            )

    def delete_tunnel(self, tunnel_id: str):
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM tunnels WHERE tunnel_id=?", (tunnel_id,))

    def delete_tunnels_for_client(self, client_id: str):
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM tunnels WHERE client_id=?", (client_id,))

    def purge_stale(self, max_age_seconds: float):
        """Remove bookkeeping rows that haven't been touched in a long time.

        This is what makes previously-used subdomains/ports eventually
        available for reuse by other clients if the original owner never
        comes back.
        """
        cutoff = time.time() - max_age_seconds
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM tunnels WHERE last_seen < ?", (cutoff,))
            self._conn.execute("DELETE FROM clients WHERE last_seen < ?", (cutoff,))

    def close(self):
        with self._lock:
            self._conn.close()
