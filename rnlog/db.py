"""SQLite storage for rnlog telemetry data."""

import json
import sqlite3
import time
from pathlib import Path

DEFAULT_DB_DIR = Path.home() / ".rnlog"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "telemetry.db"


def open_db(path: Path = None) -> sqlite3.Connection:
    """Open (and initialise if needed) the telemetry database."""
    if path is None:
        path = DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            interface TEXT NOT NULL,
            interface_hash TEXT NOT NULL,
            reading TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_readings_iface "
        "ON readings(interface_hash, ts)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_readings_ts "
        "ON readings(ts)"
    )
    conn.commit()
    return conn


def store_reading(conn: sqlite3.Connection, ts: float,
                  interface: str, interface_hash: str,
                  reading: dict) -> int:
    """Store a single reading. Returns the row id."""
    reading_json = json.dumps(reading, separators=(",", ":"))
    cur = conn.execute(
        "INSERT INTO readings (ts, interface, interface_hash, reading) "
        "VALUES (?, ?, ?, ?)",
        (ts, interface, interface_hash, reading_json),
    )
    return cur.lastrowid


def query_readings(conn: sqlite3.Connection,
                   interface: str = None,
                   since: float = None,
                   until: float = None,
                   limit: int = None) -> list[dict]:
    """Query stored readings with optional filters."""
    sql = "SELECT id, ts, interface, interface_hash, reading FROM readings WHERE 1=1"
    params = []

    if interface:
        sql += " AND interface = ?"
        params.append(interface)
    if since:
        sql += " AND ts >= ?"
        params.append(since)
    if until:
        sql += " AND ts <= ?"
        params.append(until)

    sql += " ORDER BY ts DESC"

    if limit:
        sql += " LIMIT ?"
        params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    results = []
    for row in rows:
        results.append({
            "id": row[0],
            "ts": row[1],
            "interface": row[2],
            "interface_hash": row[3],
            "reading": json.loads(row[4]),
        })
    return results


def get_summary(conn: sqlite3.Connection) -> dict:
    """Get a summary of stored data."""
    total = conn.execute("SELECT COUNT(*) FROM readings").fetchone()[0]
    interfaces = conn.execute(
        "SELECT interface, COUNT(*), MIN(ts), MAX(ts) "
        "FROM readings GROUP BY interface"
    ).fetchall()

    return {
        "total_readings": total,
        "interfaces": [
            {
                "name": row[0],
                "readings": row[1],
                "first": row[2],
                "last": row[3],
            }
            for row in interfaces
        ],
    }
