"""SQLite persistence: sessions, observations, labels, retention, purge.

Design constraints that come straight from the responsible-use posture:

* Everything stays on this machine. There is no sync, no upload, no telemetry.
* Retention is bounded **by default**, not opt-in. Old observations age out.
* There is a single view that says exactly what is stored, and one call that
  destroys all of it.
* Labels and "this is mine" markings live in their own table so they survive
  purges of the raw capture data — losing your own annotations because you
  cleared history would be obnoxious.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from blemon.device import Device
from blemon.models import AddressType, Advertisement, LinkEvent, PduType

SCHEMA_VERSION = 1

#: Keep raw per-packet observations for this long by default. Device summaries
#: are far smaller and are kept longer.
DEFAULT_OBSERVATION_RETENTION_DAYS = 7
DEFAULT_SESSION_RETENTION_DAYS = 90

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    started_at    REAL NOT NULL,
    ended_at      REAL,
    backend       TEXT,
    capabilities  TEXT,
    notes         TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    key           TEXT NOT NULL,
    address       TEXT NOT NULL,
    address_type  TEXT,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    packet_count  INTEGER NOT NULL DEFAULT 0,
    category      TEXT,
    label         TEXT,
    exposure      INTEGER,
    is_tracker    INTEGER NOT NULL DEFAULT 0,
    snapshot      TEXT NOT NULL,
    PRIMARY KEY (session_id, key)
);
CREATE INDEX IF NOT EXISTS idx_devices_key      ON devices(key);
CREATE INDEX IF NOT EXISTS idx_devices_lastseen ON devices(last_seen);

CREATE TABLE IF NOT EXISTS observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    device_key  TEXT NOT NULL,
    address     TEXT NOT NULL,
    address_type TEXT,
    ts          REAL NOT NULL,
    rssi        INTEGER,
    channel     INTEGER,
    pdu_type    TEXT,
    phy         TEXT,
    scan_rsp    INTEGER NOT NULL DEFAULT 0,
    source      TEXT,
    raw         BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_obs_session ON observations(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_obs_device  ON observations(device_key, ts);
-- Retention deletes by timestamp across all sessions; without a ts-leading
-- index that DELETE would full-scan the whole table.
CREATE INDEX IF NOT EXISTS idx_obs_ts      ON observations(ts);

CREATE TABLE IF NOT EXISTS link_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    device_key  TEXT,
    ts          REAL NOT NULL,
    kind        TEXT NOT NULL,
    direction   TEXT,
    encrypted   INTEGER NOT NULL DEFAULT 0,
    summary     TEXT,
    detail      TEXT,
    raw         BLOB
);
CREATE INDEX IF NOT EXISTS idx_link_session ON link_events(session_id, ts);

-- User annotations. Deliberately outside the session tables so they survive
-- a purge of captured data.
CREATE TABLE IF NOT EXISTS labels (
    key        TEXT PRIMARY KEY,
    label      TEXT,
    is_mine    INTEGER NOT NULL DEFAULT 0,
    notes      TEXT,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    key          TEXT PRIMARY KEY,
    session_id   INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    device_key   TEXT,
    level        TEXT,
    title        TEXT,
    explanation  TEXT,
    evidence     TEXT,
    raised_at    REAL NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
"""


@dataclass
class RetentionPolicy:
    observation_days: int = DEFAULT_OBSERVATION_RETENTION_DAYS
    session_days: int = DEFAULT_SESSION_RETENTION_DAYS
    #: Hard cap so a long unattended run cannot fill a Pi's SD card.
    max_observations: int = 5_000_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_days": self.observation_days,
            "session_days": self.session_days,
            "max_observations": self.max_observations,
        }


def default_db_path() -> Path:
    base = Path.home() / ".local" / "share" / "ble-monitor"
    base.mkdir(parents=True, exist_ok=True)
    return base / "capture.db"


class Store:
    """Thread-safe SQLite wrapper. One connection, guarded by a lock.

    Capture is a single writer at modest rates, so a lock is simpler and more
    predictable than a connection pool, and it keeps WAL mode honest.
    """

    def __init__(self, path: str | Path | None = None, retention: RetentionPolicy | None = None):
        self.path = Path(path) if path else default_db_path()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.retention = retention or RetentionPolicy()
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- sessions ----------------------------------------------------------

    def start_session(
        self, name: str, backend: str = "", capabilities: dict | None = None
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO sessions(name, started_at, backend, capabilities) VALUES(?,?,?,?)",
                (name, time.time(), backend, json.dumps(capabilities or {})),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def end_session(self, session_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET ended_at=? WHERE id=? AND ended_at IS NULL",
                (time.time(), session_id),
            )
            self._conn.commit()

    def rename_session(self, session_id: int, name: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE sessions SET name=? WHERE id=?", (name, session_id))
            self._conn.commit()

    def sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT s.*,
                       (SELECT COUNT(*) FROM devices d WHERE d.session_id = s.id)      AS device_count,
                       (SELECT COUNT(*) FROM observations o WHERE o.session_id = s.id) AS observation_count
                FROM sessions s ORDER BY s.started_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["capabilities"] = json.loads(d.get("capabilities") or "{}")
            d["duration"] = (d.get("ended_at") or time.time()) - d["started_at"]
            out.append(d)
        return out

    def session(self, session_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT s.*,
                       (SELECT COUNT(*) FROM devices d WHERE d.session_id = s.id)      AS device_count,
                       (SELECT COUNT(*) FROM observations o WHERE o.session_id = s.id) AS observation_count
                FROM sessions s WHERE s.id = ?
                """,
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["capabilities"] = json.loads(d.get("capabilities") or "{}")
        d["duration"] = (d.get("ended_at") or time.time()) - d["started_at"]
        return d

    def delete_session(self, session_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE id=?", (session_id,))
            self._conn.commit()

    # -- writes ------------------------------------------------------------

    def record_observations(
        self, session_id: int, rows: list[tuple[str, Advertisement]]
    ) -> None:
        """Bulk-insert advertisements. ``rows`` is ``(device_key, advertisement)``."""
        if not rows:
            return
        payload = [
            (
                session_id,
                key,
                adv.address,
                adv.address_type.value,
                adv.timestamp,
                adv.rssi,
                adv.channel,
                adv.pdu_type.value,
                adv.phy,
                1 if adv.scan_response else 0,
                adv.source,
                adv.raw,
            )
            for key, adv in rows
        ]
        with self._lock:
            self._conn.executemany(
                """INSERT INTO observations
                   (session_id, device_key, address, address_type, ts, rssi, channel,
                    pdu_type, phy, scan_rsp, source, raw)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                payload,
            )
            self._conn.commit()

    def record_link_events(self, session_id: int, events: list[tuple[str | None, LinkEvent]]) -> None:
        if not events:
            return
        payload = [
            (
                session_id,
                key,
                e.timestamp,
                e.kind,
                e.direction,
                1 if e.encrypted else 0,
                e.summary,
                json.dumps(e.detail, default=str),
                e.raw,
            )
            for key, e in events
        ]
        with self._lock:
            self._conn.executemany(
                """INSERT INTO link_events
                   (session_id, device_key, ts, kind, direction, encrypted, summary, detail, raw)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                payload,
            )
            self._conn.commit()

    def snapshot_devices(self, session_id: int, devices: list[Device]) -> None:
        """Upsert the current per-device summary for this session."""
        if not devices:
            return
        payload = []
        for d in devices:
            exposure = d.exposure()
            payload.append(
                (
                    session_id,
                    d.key,
                    d.address,
                    d.address_type.value,
                    d.first_seen,
                    d.last_seen,
                    d.packet_count,
                    d.category.value,
                    d.display_name,
                    exposure.score,
                    1 if d.is_tracker else 0,
                    json.dumps(d.to_dict(), default=str),
                )
            )
        with self._lock:
            self._conn.executemany(
                """INSERT INTO devices
                   (session_id, key, address, address_type, first_seen, last_seen,
                    packet_count, category, label, exposure, is_tracker, snapshot)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(session_id, key) DO UPDATE SET
                     address=excluded.address,
                     address_type=excluded.address_type,
                     last_seen=excluded.last_seen,
                     packet_count=excluded.packet_count,
                     category=excluded.category,
                     label=excluded.label,
                     exposure=excluded.exposure,
                     is_tracker=excluded.is_tracker,
                     snapshot=excluded.snapshot""",
                payload,
            )
            self._conn.commit()

    def record_alerts(self, session_id: int, alerts: list[Any]) -> None:
        if not alerts:
            return
        payload = [
            (
                a.key,
                session_id,
                a.device_key,
                a.level.value,
                a.title,
                a.explanation,
                json.dumps(a.evidence),
                a.raised_at,
                1 if a.acknowledged else 0,
            )
            for a in alerts
        ]
        with self._lock:
            self._conn.executemany(
                """INSERT INTO alerts
                   (key, session_id, device_key, level, title, explanation, evidence,
                    raised_at, acknowledged)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(key) DO UPDATE SET
                     level=excluded.level, title=excluded.title,
                     explanation=excluded.explanation, evidence=excluded.evidence""",
                payload,
            )
            self._conn.commit()

    def acknowledge_alert(self, key: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE alerts SET acknowledged=1 WHERE key=?", (key,))
            self._conn.commit()

    # -- labels ------------------------------------------------------------

    def set_label(
        self,
        key: str,
        label: str | None = None,
        is_mine: bool | None = None,
        notes: str | None = None,
    ) -> None:
        existing = self.get_label(key) or {}
        with self._lock:
            self._conn.execute(
                """INSERT INTO labels(key, label, is_mine, notes, updated_at)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(key) DO UPDATE SET
                     label=excluded.label, is_mine=excluded.is_mine,
                     notes=excluded.notes, updated_at=excluded.updated_at""",
                (
                    key,
                    label if label is not None else existing.get("label"),
                    int(is_mine if is_mine is not None else existing.get("is_mine", 0)),
                    notes if notes is not None else existing.get("notes"),
                    time.time(),
                ),
            )
            self._conn.commit()

    def get_label(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM labels WHERE key=?", (key,)).fetchone()
        return dict(row) if row else None

    def all_labels(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM labels").fetchall()
        return {r["key"]: dict(r) for r in rows}

    # -- reads -------------------------------------------------------------

    def devices(
        self,
        session_id: int | None = None,
        since: float | None = None,
        category: str | None = None,
        tracker_only: bool = False,
        search: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        sql = ["SELECT * FROM devices WHERE 1=1"]
        args: list[Any] = []
        if session_id is not None:
            sql.append("AND session_id=?")
            args.append(session_id)
        if since is not None:
            sql.append("AND last_seen>=?")
            args.append(since)
        if category:
            sql.append("AND category=?")
            args.append(category)
        if tracker_only:
            sql.append("AND is_tracker=1")
        if search:
            # Escape LIKE wildcards so a search for "100%" or "A_" is a literal
            # match rather than a pattern that silently matches far too much.
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            sql.append(
                "AND (label LIKE ? ESCAPE '\\' OR address LIKE ? ESCAPE '\\' "
                "OR key LIKE ? ESCAPE '\\')"
            )
            args += [f"%{escaped}%"] * 3
        sql.append("ORDER BY last_seen DESC LIMIT ?")
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(" ".join(sql), args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["snapshot"] = json.loads(d["snapshot"])
            out.append(d)
        return out

    def device_history(self, key: str, limit: int = 20) -> list[dict[str, Any]]:
        """Every session in which this device key was seen."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT d.session_id, d.first_seen, d.last_seen, d.packet_count,
                          s.name AS session_name, s.started_at
                   FROM devices d JOIN sessions s ON s.id = d.session_id
                   WHERE d.key=? ORDER BY d.last_seen DESC LIMIT ?""",
                (key, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def session_counts_for_devices(self, keys: list[str]) -> dict[str, int]:
        """How many distinct sessions each key has appeared in.

        This is what turns "a tracker is here" into "a tracker has been with
        you in three different places", which is the alert that matters.
        """
        if not keys:
            return {}
        marks = ",".join("?" * len(keys))
        with self._lock:
            rows = self._conn.execute(
                f"""SELECT key, COUNT(DISTINCT session_id) AS n FROM devices
                    WHERE key IN ({marks}) GROUP BY key""",
                keys,
            ).fetchall()
        return {r["key"]: int(r["n"]) for r in rows}

    def observations(
        self,
        session_id: int | None = None,
        device_key: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 5000,
    ) -> list[dict[str, Any]]:
        sql = ["SELECT * FROM observations WHERE 1=1"]
        args: list[Any] = []
        if session_id is not None:
            sql.append("AND session_id=?")
            args.append(session_id)
        if device_key:
            sql.append("AND device_key=?")
            args.append(device_key)
        if since is not None:
            sql.append("AND ts>=?")
            args.append(since)
        if until is not None:
            sql.append("AND ts<=?")
            args.append(until)
        sql.append("ORDER BY ts ASC LIMIT ?")
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(" ".join(sql), args).fetchall()
        return [dict(r) for r in rows]

    def replay(self, session_id: int, batch: int = 2000):
        """Yield advertisements from a recorded session in insertion order.

        Keyset pagination on the integer primary key rather than LIMIT/OFFSET:
        OFFSET re-walks the index from row zero for every batch, which is
        quadratic over a multi-million-row session and stalls both live replay
        and PCAP export. ``id`` is autoincrement, so within one session it is
        already in capture order.
        """
        after = 0
        while True:
            with self._lock:
                rows = self._conn.execute(
                    """SELECT * FROM observations WHERE session_id=? AND id>?
                       ORDER BY id ASC LIMIT ?""",
                    (session_id, after, batch),
                ).fetchall()
            if not rows:
                return
            after = rows[-1]["id"]
            for r in rows:
                yield r["device_key"], Advertisement(
                    address=r["address"],
                    timestamp=r["ts"],
                    rssi=r["rssi"],
                    address_type=AddressType(r["address_type"])
                    if r["address_type"] in AddressType._value2member_map_
                    else AddressType.UNKNOWN,
                    raw=bytes(r["raw"]),
                    channel=r["channel"],
                    pdu_type=PduType(r["pdu_type"])
                    if r["pdu_type"] in PduType._value2member_map_
                    else PduType.UNKNOWN,
                    phy=r["phy"] or "1M",
                    scan_response=bool(r["scan_rsp"]),
                    source=r["source"] or "replay",
                )

    def link_events(self, session_id: int, device_key: str | None = None, limit: int = 2000):
        sql = ["SELECT * FROM link_events WHERE session_id=?"]
        args: list[Any] = [session_id]
        if device_key:
            sql.append("AND device_key=?")
            args.append(device_key)
        sql.append("ORDER BY ts ASC LIMIT ?")
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(" ".join(sql), args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d["detail"] or "{}")
            d["raw"] = bytes(d["raw"] or b"").hex()
            # The live WebSocket feed emits link events keyed "timestamp"; keep
            # the stored-read path the same shape so the web client (which reads
            # e.timestamp) does not render "Invalid Date" for replayed captures.
            d["timestamp"] = d.pop("ts", None)
            out.append(d)
        return out

    def alerts(self, include_acknowledged: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM alerts"
        if not include_acknowledged:
            sql += " WHERE acknowledged=0"
        sql += " ORDER BY raised_at DESC"
        with self._lock:
            rows = self._conn.execute(sql).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["evidence"] = json.loads(d["evidence"] or "[]")
            out.append(d)
        return out

    # -- retention and purge ----------------------------------------------

    def what_is_stored(self) -> dict[str, Any]:
        """The honest answer to 'what does this thing have on my neighbours?'"""
        with self._lock:
            counts = {
                name: int(
                    self._conn.execute(f"SELECT COUNT(*) AS n FROM {name}").fetchone()["n"]
                )
                for name in ("sessions", "devices", "observations", "link_events", "labels", "alerts")
            }
            oldest = self._conn.execute(
                "SELECT MIN(ts) AS t FROM observations"
            ).fetchone()["t"]
            newest = self._conn.execute(
                "SELECT MAX(ts) AS t FROM observations"
            ).fetchone()["t"]
            distinct_addresses = int(
                self._conn.execute(
                    "SELECT COUNT(DISTINCT address) AS n FROM observations"
                ).fetchone()["n"]
            )
        # Count the WAL and shared-memory side files too. In WAL mode recent
        # writes live in capture.db-wal until checkpoint, so reporting only the
        # main file understates real on-disk usage right after a busy capture —
        # exactly when a user checks the transparency view.
        size = 0
        if str(self.path) != ":memory:":
            for suffix in ("", "-wal", "-shm"):
                side = self.path.with_name(self.path.name + suffix)
                if side.exists():
                    size += side.stat().st_size
        return {
            "database_path": str(self.path),
            "size_bytes": size,
            "size_human": _human_bytes(size),
            "counts": counts,
            "distinct_addresses": distinct_addresses,
            "oldest_observation": oldest,
            "newest_observation": newest,
            "retention": self.retention.to_dict(),
            "note": (
                "Everything listed here is on this machine only. Nothing is uploaded "
                "anywhere. Use purge to destroy all of it."
            ),
        }

    def enforce_retention(self, now: float | None = None) -> dict[str, int]:
        """Delete anything past the retention policy. Safe to call frequently."""
        now = now or time.time()
        obs_cutoff = now - self.retention.observation_days * 86400
        ses_cutoff = now - self.retention.session_days * 86400
        removed = {}
        with self._lock:
            cur = self._conn.execute("DELETE FROM observations WHERE ts < ?", (obs_cutoff,))
            removed["observations"] = cur.rowcount
            cur = self._conn.execute("DELETE FROM link_events WHERE ts < ?", (obs_cutoff,))
            removed["link_events"] = cur.rowcount
            cur = self._conn.execute("DELETE FROM sessions WHERE started_at < ?", (ses_cutoff,))
            removed["sessions"] = cur.rowcount

            total = int(
                self._conn.execute("SELECT COUNT(*) AS n FROM observations").fetchone()["n"]
            )
            if total > self.retention.max_observations:
                excess = total - self.retention.max_observations
                cur = self._conn.execute(
                    "DELETE FROM observations WHERE id IN "
                    "(SELECT id FROM observations ORDER BY ts ASC LIMIT ?)",
                    (excess,),
                )
                removed["observations"] = removed.get("observations", 0) + cur.rowcount
            self._conn.commit()
        return {k: v for k, v in removed.items() if v}

    def purge(self, keep_labels: bool = True) -> None:
        """Destroy captured data. One call, no confirmation dialogs in here —
        the confirmation belongs in the UI, not the storage layer."""
        with self._lock:
            for table in ("alerts", "link_events", "observations", "devices", "sessions"):
                self._conn.execute(f"DELETE FROM {table}")
            if not keep_labels:
                self._conn.execute("DELETE FROM labels")
            self._conn.commit()
            self._conn.execute("VACUUM")

    def vacuum(self) -> None:
        with self._lock:
            self._conn.execute("VACUUM")


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"
