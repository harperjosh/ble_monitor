"""The live hub: one place where capture, decode, identity and storage meet.

Responsibilities, in order of how often they run:

* **per packet** — parse, attach to a device record, push to the waterfall feed
  and to any live subscribers.
* **per tick (1s)** — re-identify devices that changed, broadcast the updated
  snapshot.
* **per sweep (10s)** — correlate MAC rotation, re-evaluate tracker alerts,
  snapshot device summaries to SQLite, retire devices that have gone silent.

Two things it deliberately does *not* do: transmit anything, and grow without
bound. Devices that go quiet are retired from memory after a while; their
history stays in the database.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from blemon.capture.base import BackendStatus, CaptureBackend
from blemon.decode import parse
from blemon.device import Device
from blemon.identity import apply_links, evaluate_all, find_links, identify
from blemon.models import Advertisement, LinkEvent, ParsedAdvertisement
from blemon.store import Store
from blemon.translate import describe_room

#: A device that has not advertised for this long is retired from the live view.
DEFAULT_RETIRE_AFTER = 180.0
#: How many recent packets to keep for the waterfall.
FEED_LENGTH = 600
#: How many link events to keep in memory.
LINK_FEED_LENGTH = 400


@dataclass
class HubStats:
    started_at: float = field(default_factory=time.time)
    packets: int = 0
    link_events: int = 0
    dropped: int = 0
    parse_errors: int = 0
    devices_seen: int = 0
    last_packet_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        uptime = time.time() - self.started_at
        return {
            "started_at": self.started_at,
            "uptime": round(uptime, 1),
            "packets": self.packets,
            "link_events": self.link_events,
            "dropped": self.dropped,
            "parse_errors": self.parse_errors,
            "devices_seen": self.devices_seen,
            "last_packet_at": self.last_packet_at,
            "packets_per_second": round(self.packets / uptime, 2) if uptime > 1 else 0.0,
        }


class Hub:
    def __init__(
        self,
        backend: CaptureBackend,
        store: Store | None = None,
        session_name: str = "live",
        persist: bool = True,
        retire_after: float = DEFAULT_RETIRE_AFTER,
    ) -> None:
        self.backend = backend
        self.store = store
        self.persist = persist and store is not None
        self.session_name = session_name
        self.retire_after = retire_after

        self.devices: dict[str, Device] = {}
        self.feed: deque[dict[str, Any]] = deque(maxlen=FEED_LENGTH)
        self.link_feed: deque[dict[str, Any]] = deque(maxlen=LINK_FEED_LENGTH)
        self.alerts: list[Any] = []
        self.stats = HubStats()
        self.session_id: int | None = None
        self.backend_status = BackendStatus("idle")

        self._subscribers: set[asyncio.Queue] = set()
        self._dirty: set[str] = set()
        self._pending_observations: list[tuple[str, Advertisement]] = []
        self._pending_link_events: list[tuple[str | None, LinkEvent]] = []
        self._tasks: list[asyncio.Task] = []
        self._stopping = False
        self._labels: dict[str, dict[str, Any]] = {}
        self._on_event: list[Callable[[str, dict], None]] = []

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self.store is not None:
            self._labels = self.store.all_labels()
            if self.persist:
                self.session_id = self.store.start_session(
                    self.session_name,
                    backend=self.backend.name,
                    capabilities=self.backend.capabilities.to_dict(),
                )
        await self.backend.start()
        self._tasks = [
            asyncio.create_task(self._ingest(), name="blemon-ingest"),
            asyncio.create_task(self._tick(), name="blemon-tick"),
            asyncio.create_task(self._sweep(), name="blemon-sweep"),
        ]

    async def stop(self) -> None:
        self._stopping = True
        await self.backend.stop()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks.clear()
        self._flush()
        if self.store is not None and self.session_id is not None:
            self.store.snapshot_devices(self.session_id, list(self.devices.values()))
            self.store.end_session(self.session_id)

    async def wait(self) -> None:
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    # -- subscriptions -----------------------------------------------------

    def subscribe(self, maxsize: int = 64) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def _broadcast(self, kind: str, payload: dict[str, Any]) -> None:
        message = {"type": kind, "at": time.time(), **payload}
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                # A slow client must not stall capture. Drop its oldest and
                # keep going; the next snapshot resyncs it completely.
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
                with contextlib.suppress(asyncio.QueueFull):
                    queue.put_nowait(message)
        for hook in self._on_event:
            with contextlib.suppress(Exception):
                hook(kind, message)

    def on_event(self, hook: Callable[[str, dict], None]) -> None:
        self._on_event.append(hook)

    # -- ingest ------------------------------------------------------------

    async def _ingest(self) -> None:
        async for event in self.backend.stream():
            if self._stopping:
                return
            self.ingest(event)

    def ingest(self, event: Advertisement | LinkEvent | BackendStatus) -> None:
        """Feed one event in directly.

        The capture loop calls this, and so can anything else that has events
        from somewhere other than a live radio — a test, an importer, or an
        embedder driving the hub itself.
        """
        if isinstance(event, Advertisement):
            self._on_advertisement(event)
        elif isinstance(event, LinkEvent):
            self._on_link_event(event)
        elif isinstance(event, BackendStatus):
            self.backend_status = event
            self._broadcast("backend_status", {"status": event.to_dict()})

    def refresh(self) -> None:
        """Run the periodic work once, synchronously.

        The sweep normally happens on a timer. Exposing it directly means a
        caller can get a fully settled hub — identified, correlated, alerted
        and persisted — without waiting on wall-clock time.
        """
        for key in list(self._dirty):
            device = self.devices.get(key)
            if device is not None:
                device.identification = identify(device)
        self._dirty.clear()
        self._flush()
        self._correlate()
        self._refresh_alerts()
        if self.store is not None and self.session_id is not None:
            self.store.snapshot_devices(self.session_id, list(self.devices.values()))

    def _on_advertisement(self, adv: Advertisement) -> None:
        parsed = parse(adv)
        self.stats.packets += 1
        self.stats.last_packet_at = adv.timestamp
        if parsed.parse_errors:
            self.stats.parse_errors += 1

        key = self._resolve_key(adv.address)
        device = self.devices.get(key)
        if device is None:
            device = Device(
                key=key,
                address=adv.address,
                address_type=adv.address_type,
                first_seen=adv.timestamp,
                last_seen=adv.timestamp,
            )
            self._apply_label(device)
            self.devices[key] = device
            self.stats.devices_seen += 1
        device.observe(parsed)
        self._dirty.add(key)

        row = self._feed_row(device, parsed)
        self.feed.append(row)
        self._broadcast("packet", {"packet": row})

        if self.persist and self.session_id is not None:
            self._pending_observations.append((key, adv))
            if len(self._pending_observations) >= 250:
                self._flush()

    def _on_link_event(self, event: LinkEvent) -> None:
        self.stats.link_events += 1
        key = self._resolve_key(event.address) if event.address else None
        device = self.devices.get(key) if key else None
        if device is not None:
            device.link_event_count += 1
            if event.encrypted:
                device.encrypted_link_seen = True
            elif event.kind in ("gatt", "data"):
                device.plaintext_link_seen = True
            self._dirty.add(device.key)

        from blemon.decode.link import explain

        row = {**event.to_dict(), "device_key": key, "english": explain(event)}
        self.link_feed.append(row)
        self._broadcast("link_event", {"event": row})
        if self.persist and self.session_id is not None:
            self._pending_link_events.append((key, event))

    def _resolve_key(self, address: str | None) -> str:
        """Map an address to its cluster key, following continuity merges."""
        if address is None:
            return ""
        if address in self.devices:
            return address
        for key, device in self.devices.items():
            if address in device.addresses_seen:
                return key
        return address

    def _apply_label(self, device: Device) -> None:
        entry = self._labels.get(device.key)
        if entry:
            device.user_label = entry.get("label")
            device.is_mine = bool(entry.get("is_mine"))
            device.notes = entry.get("notes")

    def _feed_row(self, device: Device, parsed: ParsedAdvertisement) -> dict[str, Any]:
        adv = parsed.advertisement
        decodings = parsed.decodings
        return {
            "t": adv.timestamp,
            "device_key": device.key,
            "address": adv.address,
            "address_type": adv.address_type.value,
            "label": device.display_name,
            "category": device.category.value,
            "rssi": adv.rssi,
            "channel": adv.channel,
            "pdu_type": adv.pdu_type.value,
            "phy": adv.phy,
            "length": len(adv.raw),
            "raw": adv.raw.hex(),
            "protocols": parsed.protocols,
            "summary": decodings[0].summary if decodings else (parsed.local_name or "advertisement"),
            "english": decodings[0].english if decodings else "",
            "tags": sorted({t for d in decodings for t in d.tags}),
        }

    def _flush(self) -> None:
        if self.store is None or self.session_id is None:
            self._pending_observations.clear()
            self._pending_link_events.clear()
            return
        if self._pending_observations:
            self.store.record_observations(self.session_id, self._pending_observations)
            self._pending_observations = []
        if self._pending_link_events:
            self.store.record_link_events(self.session_id, self._pending_link_events)
            self._pending_link_events = []

    # -- periodic work -----------------------------------------------------

    async def _tick(self) -> None:
        while not self._stopping:
            await asyncio.sleep(1.0)
            if not self._dirty:
                continue
            changed = []
            for key in list(self._dirty):
                device = self.devices.get(key)
                if device is None:
                    continue
                device.identification = identify(device)
                changed.append(device.to_dict())
            self._dirty.clear()
            self._broadcast("devices", {"devices": changed, "stats": self.stats.to_dict()})

    async def _sweep(self) -> None:
        while not self._stopping:
            await asyncio.sleep(10.0)
            self._flush()
            self._correlate()
            self._retire()
            self._refresh_alerts()
            if self.store is not None and self.session_id is not None:
                self.store.snapshot_devices(self.session_id, list(self.devices.values()))
            self.stats.dropped = getattr(self.backend, "dropped", 0)
            self._broadcast("snapshot", self.snapshot())

    def _correlate(self) -> None:
        links = find_links(list(self.devices.values()))
        if not links:
            return
        before = set(self.devices)
        apply_links(self.devices, links)
        removed = before - set(self.devices)
        if removed:
            for key in removed:
                self._dirty.discard(key)
            self._broadcast("merged", {"removed": sorted(removed), "links": len(links)})

    def _retire(self) -> None:
        cutoff = time.time() - self.retire_after
        gone = [k for k, d in self.devices.items() if d.last_seen < cutoff]
        for key in gone:
            self.devices.pop(key, None)
            self._dirty.discard(key)
        if gone:
            self._broadcast("retired", {"keys": gone})

    def _refresh_alerts(self) -> None:
        counts: dict[str, int] = {}
        if self.store is not None:
            counts = self.store.session_counts_for_devices(list(self.devices))
        self.alerts = evaluate_all(list(self.devices.values()), session_counts=counts)
        if self.store is not None and self.session_id is not None and self.alerts:
            self.store.record_alerts(self.session_id, self.alerts)
        self._broadcast("alerts", {"alerts": [a.to_dict() for a in self.alerts]})

    # -- labels ------------------------------------------------------------

    def set_label(
        self,
        key: str,
        label: str | None = None,
        is_mine: bool | None = None,
        notes: str | None = None,
    ) -> Device | None:
        device = self.devices.get(key)
        if device is not None:
            if label is not None:
                device.user_label = label or None
            if is_mine is not None:
                device.is_mine = is_mine
            if notes is not None:
                device.notes = notes or None
            device.identification = identify(device)
            self._dirty.add(key)
        if self.store is not None:
            self.store.set_label(key, label=label, is_mine=is_mine, notes=notes)
            self._labels = self.store.all_labels()
        return device

    def acknowledge_alert(self, alert_key: str) -> None:
        for alert in self.alerts:
            if alert.key == alert_key:
                alert.acknowledged = True
        if self.store is not None:
            self.store.acknowledge_alert(alert_key)

    # -- views -------------------------------------------------------------

    def device_list(self) -> list[Device]:
        return sorted(self.devices.values(), key=lambda d: -(d.smoothed_rssi or -127))

    def snapshot(self, include_feed: bool = False) -> dict[str, Any]:
        devices = self.device_list()
        payload: dict[str, Any] = {
            "devices": [d.to_dict() for d in devices],
            "stats": self.stats.to_dict(),
            "alerts": [a.to_dict() for a in self.alerts],
            "summary": describe_room(devices),
            "exposure": self.exposure_summary(),
            "backend": self.backend.describe(),
            "session_id": self.session_id,
        }
        if include_feed:
            payload["feed"] = list(self.feed)
            payload["link_feed"] = list(self.link_feed)
        return payload

    def exposure_summary(self) -> dict[str, Any]:
        devices = list(self.devices.values())
        if not devices:
            return {
                "total": 0,
                "bands": {},
                "rotating": 0,
                "stable": 0,
                "named": 0,
                "plaintext_content": 0,
                "trackers": 0,
                "median_score": 0,
                "top_reasons": [],
                "with_link_data": 0,
                "encrypted_links": 0,
                "plaintext_links": 0,
            }
        scores = []
        bands: dict[str, int] = {}
        reasons: dict[str, int] = {}
        for d in devices:
            exposure = d.exposure()
            scores.append(exposure.score)
            bands[exposure.band] = bands.get(exposure.band, 0) + 1
            for reason in exposure.reasons:
                reasons[reason] = reasons.get(reason, 0) + 1
        scores.sort()
        return {
            "total": len(devices),
            "bands": bands,
            "rotating": sum(1 for d in devices if d.rotates_address),
            "stable": sum(1 for d in devices if not d.rotates_address),
            "named": sum(1 for d in devices if d.names),
            "plaintext_content": sum(1 for d in devices if "plaintext_content" in d.tags),
            "trackers": sum(1 for d in devices if d.is_tracker),
            "median_score": scores[len(scores) // 2],
            "top_reasons": sorted(reasons.items(), key=lambda kv: -kv[1])[:8],
            "with_link_data": sum(1 for d in devices if d.link_event_count),
            "encrypted_links": sum(1 for d in devices if d.encrypted_link_seen),
            "plaintext_links": sum(1 for d in devices if d.plaintext_link_seen),
        }

    def timeline(self, buckets: int = 60) -> dict[str, Any]:
        """Presence over time, for the timeline view."""
        now = time.time()
        start = self.stats.started_at
        span = max(1.0, now - start)
        width = span / buckets
        rows = []
        for device in self.device_list():
            first = max(0, int((device.first_seen - start) / width))
            last = min(buckets - 1, int((device.last_seen - start) / width))
            rows.append(
                {
                    "key": device.key,
                    "label": device.display_name,
                    "category": device.category.value,
                    "first_bucket": first,
                    "last_bucket": last,
                    "first_seen": device.first_seen,
                    "last_seen": device.last_seen,
                    "packet_count": device.packet_count,
                    "is_tracker": device.is_tracker,
                }
            )
        return {"start": start, "end": now, "buckets": buckets, "bucket_seconds": width, "rows": rows}
