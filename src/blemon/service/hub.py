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
import threading
import time
from collections import deque
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
#: The 10s sweep enforces retention every this-many sweeps (~5 minutes). Deleting
#: aged-out rows more often than that is pointless churn on an SD card.
RETENTION_EVERY_SWEEPS = 30


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
        #: address (current or any historical) -> cluster key, so the hot path
        #: never has to scan every device to find who a rotated address belongs
        #: to. Kept in step with device create, observe, merge and retire.
        self._address_index: dict[str, str] = {}
        #: Alert keys the user has dismissed. The sweep regenerates Alert objects
        #: from scratch, so without this the acknowledged flag would be lost and
        #: dismissed alerts would reappear within one sweep.
        self._acknowledged: set[str] = set()
        #: Guards structural changes to self.devices against the sync API
        #: endpoints, which read it from Starlette's threadpool while the capture
        #: task mutates it on the event loop.
        self._lock = threading.RLock()
        self._sweeps = 0

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self.store is not None:
            self._labels = self.store.all_labels()
            # Seed the dismissed set from storage so acknowledgements survive a
            # restart as well as each sweep.
            with contextlib.suppress(Exception):
                self._acknowledged = {
                    a["key"] for a in self.store.alerts(include_acknowledged=True)
                    if a.get("acknowledged")
                }
        # Start the radio before opening a session row. If the backend fails to
        # start, this raises and no zombie session is left behind to become the
        # bogus "most recent" capture for a later export.
        await self.backend.start()
        if self.persist and self.store is not None:
            self.session_id = self.store.start_session(
                self.session_name,
                backend=self.backend.name,
                capabilities=self.backend.capabilities.to_dict(),
            )
        self._tasks = [
            asyncio.create_task(self._ingest(), name="blemon-ingest"),
            asyncio.create_task(self._tick(), name="blemon-tick"),
            asyncio.create_task(self._sweep(), name="blemon-sweep"),
        ]

    async def stop(self) -> None:
        self._stopping = True
        with contextlib.suppress(Exception):
            await self.backend.stop()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            # A task may have already died with a non-cancel error; awaiting it
            # re-raises, which must not abort the final flush below.
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._tasks.clear()
        # Best-effort final persistence — never let a store error prevent the
        # session from being closed cleanly.
        with contextlib.suppress(Exception):
            self._flush()
        if self.store is not None and self.session_id is not None:
            with contextlib.suppress(Exception):
                self.store.snapshot_devices(self.session_id, list(self.devices.values()))
            with contextlib.suppress(Exception):
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

    # -- ingest ------------------------------------------------------------

    async def _ingest(self) -> None:
        try:
            async for event in self.backend.stream():
                if self._stopping:
                    return
                self.ingest(event)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — surface, don't die silently
            # A backend or store error must not kill capture invisibly with the
            # socket still reporting "live". Tell every client what happened.
            self.backend_status = BackendStatus("error", f"Capture stopped: {exc}")
            self._broadcast("backend_status", {"status": self.backend_status.to_dict()})

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
            with self._lock:
                self.devices[key] = device
            self._address_index[adv.address] = key
            self.stats.devices_seen += 1
        elif adv.address not in self._address_index:
            self._address_index[adv.address] = key
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
        """Map an address to its cluster key, following continuity merges.

        O(1) via a reverse index. After a MAC-rotation merge the device's
        current address is no longer a key of its own, so a per-packet linear
        scan over every device's ``addresses_seen`` would run on the hottest
        path in exactly the dense, rotating-address rooms this tool targets.
        """
        if address is None:
            return ""
        if address in self.devices:
            return address
        mapped = self._address_index.get(address)
        if mapped is not None and mapped in self.devices:
            return mapped
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
            try:
                self._sweeps += 1
                self._flush()
                self._correlate()
                self._retire()
                self._refresh_alerts()
                if self.store is not None and self.session_id is not None:
                    self.store.snapshot_devices(self.session_id, list(self.devices.values()))
                    # Enforce the documented retention window. Without this the
                    # observations table grows at packet rate forever and the
                    # "bounded by default" promise is dead code.
                    if self._sweeps % RETENTION_EVERY_SWEEPS == 0:
                        self.store.enforce_retention()
                self.stats.dropped = getattr(self.backend, "dropped", 0)
                self._broadcast("snapshot", self.snapshot())
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — one bad sweep must not end capture
                self._broadcast(
                    "backend_status",
                    {"status": BackendStatus("warning", f"sweep error: {exc}").to_dict()},
                )

    def _correlate(self) -> None:
        links = find_links(list(self.devices.values()))
        if not links:
            return
        before = set(self.devices)
        with self._lock:
            apply_links(self.devices, links)
        removed = before - set(self.devices)
        if removed:
            for key in removed:
                self._dirty.discard(key)
            # Survivors may have absorbed an address the user had labelled under
            # a different key; rebuild the index and re-apply labels so the
            # merge does not silently drop "this is mine" or a nickname.
            self._rebuild_address_index()
            for key in removed:
                self._reapply_labels_for(key)
            self._broadcast("merged", {"removed": sorted(removed), "links": len(links)})

    def _rebuild_address_index(self) -> None:
        self._address_index = {
            addr: key for key, device in self.devices.items() for addr in device.addresses_seen
        }

    def _reapply_labels_for(self, absorbed_key: str) -> None:
        """After a merge, re-apply any label the user stored under an address
        that now belongs to a surviving cluster."""
        entry = self._labels.get(absorbed_key)
        if not entry:
            return
        survivor_key = self._address_index.get(absorbed_key)
        survivor = self.devices.get(survivor_key) if survivor_key else None
        if survivor is None:
            return
        if entry.get("label") and not survivor.user_label:
            survivor.user_label = entry.get("label")
        survivor.is_mine = survivor.is_mine or bool(entry.get("is_mine"))
        if entry.get("notes") and not survivor.notes:
            survivor.notes = entry.get("notes")
        survivor.identification = identify(survivor)
        self._dirty.add(survivor.key)

    def _retire(self) -> None:
        cutoff = time.time() - self.retire_after
        gone = [k for k, d in self.devices.items() if d.last_seen < cutoff]
        if not gone:
            return
        with self._lock:
            for key in gone:
                device = self.devices.pop(key, None)
                self._dirty.discard(key)
                if device is not None:
                    for addr in device.addresses_seen:
                        if self._address_index.get(addr) == key:
                            self._address_index.pop(addr, None)
        self._broadcast("retired", {"keys": gone})

    def _refresh_alerts(self) -> None:
        counts: dict[str, int] = {}
        if self.store is not None:
            counts = self.store.session_counts_for_devices(list(self.devices))
        alerts = evaluate_all(list(self.devices.values()), session_counts=counts)
        # evaluate_all builds fresh Alert objects (acknowledged defaults False),
        # so re-apply the user's dismissals or a dismissed alert reappears every
        # sweep.
        for alert in alerts:
            if alert.key in self._acknowledged:
                alert.acknowledged = True
        self.alerts = alerts
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
        # Device keys are always upper-case addresses; canonicalize the incoming
        # key so a label posted for "aa:bb:.." still matches the live "AA:BB:.."
        # device (and the stored label row lines up with what _apply_label reads).
        key = key.strip().upper()
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
        self._acknowledged.add(alert_key)
        for alert in self.alerts:
            if alert.key == alert_key:
                alert.acknowledged = True
        if self.store is not None:
            self.store.acknowledge_alert(alert_key)

    # -- views -------------------------------------------------------------

    def device_list(self) -> list[Device]:
        # Materialize under the lock: these reads run in Starlette's threadpool
        # while the capture task inserts/retires on the event loop, and iterating
        # a dict being resized raises "dictionary changed size during iteration".
        with self._lock:
            snapshot = list(self.devices.values())
        return sorted(snapshot, key=lambda d: -(d.smoothed_rssi or -127))

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
        with self._lock:
            devices = list(self.devices.values())
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
            "median_score": scores[len(scores) // 2] if scores else 0,
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
