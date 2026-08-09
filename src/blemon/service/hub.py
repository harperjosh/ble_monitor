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
from blemon.identity.trackers import AlertLevel
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
#: How many observations to buffer when the store is busy. The per-packet flush
#: never waits on the store lock, so this bounds what a long VACUUM can cost in
#: memory; beyond it the oldest rows are dropped rather than growing unbounded.
MAX_PENDING_OBSERVATIONS = 20_000


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
        #: Alert key -> the level it was dismissed at. The sweep regenerates
        #: Alert objects from scratch, so without this the acknowledged flag
        #: would be lost and dismissed alerts would reappear within one sweep.
        #: Storing the *level* rather than just the key means a later escalation
        #: of the same alert still reaches the user.
        self._acknowledged: dict[str, str] = {}
        #: Guards self.devices and the Device objects in it against the sync API
        #: endpoints, which read them from Starlette's threadpool while the
        #: capture task mutates them on the event loop.
        self._lock = threading.RLock()
        self._sweeps = 0

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self.store is not None:
            self._labels = self.store.all_labels()
            # Seed the dismissed set from storage so acknowledgements survive a
            # restart as well as each sweep. Rows written before the level was
            # recorded fall back to the level the alert had when it was stored.
            with contextlib.suppress(Exception):
                self._acknowledged = {
                    a["key"]: (a.get("acknowledged_level") or a.get("level") or "")
                    for a in self.store.alerts(include_acknowledged=True)
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
        try:
            await self.backend.stop()
        except Exception as exc:  # noqa: BLE001 — report, but still shut down
            # A radio that will not close is a leaked serial port or HCI socket:
            # the next run fails with a bare "device busy" and nothing connects
            # it to this shutdown. Record it where the user can see it rather
            # than discarding it, but keep tearing the rest down.
            self.backend_status = BackendStatus("error", f"Backend did not stop cleanly: {exc}")
            self._broadcast("backend_status", {"status": self.backend_status.to_dict()})
        for task in self._tasks:
            task.cancel()
        # gather(return_exceptions=True) rather than suppressing around each
        # await: a task may have already died with a non-cancel error, and
        # swallowing CancelledError in a `with` block here would also eat a
        # cancellation aimed at stop() itself, so an outer shutdown that expects
        # it to propagate would hang instead.
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
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
            self._index_device(device)
            self.stats.devices_seen += 1
        elif adv.address not in self._address_index:
            self._address_index[adv.address] = key
        # observe() appends to rssi_history and updates the Counters that
        # to_dict()/exposure() walk from the API threadpool, so the mutation has
        # to happen under the same lock the readers take.
        with self._lock:
            device.observe(parsed)
        self._dirty.add(key)

        row = self._feed_row(device, parsed)
        self.feed.append(row)
        self._broadcast("packet", {"packet": row})

        if self.persist and self.session_id is not None:
            self._pending_observations.append((key, adv))
            if len(self._pending_observations) >= 250:
                # On the event loop: never wait on the store lock here.
                self._flush(blocking=False)

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

    def _flush(self, blocking: bool = True) -> None:
        """Write buffered rows out.

        With ``blocking=False`` — the per-packet path, which runs on the event
        loop — rows that cannot be written right now are kept for the next
        attempt rather than parking the loop behind whatever else holds the
        store lock (a VACUUM from /api/purge, a retention pass in the sweep
        thread). The buffer is capped so a store that stays busy costs bounded
        memory instead of growing at packet rate.
        """
        if self.store is None or self.session_id is None:
            self._pending_observations.clear()
            self._pending_link_events.clear()
            return
        if self._pending_observations:
            if self.store.record_observations(
                self.session_id, self._pending_observations, blocking=blocking
            ):
                self._pending_observations = []
            else:
                del self._pending_observations[:-MAX_PENDING_OBSERVATIONS]
        if self._pending_link_events:
            if self.store.record_link_events(
                self.session_id, self._pending_link_events, blocking=blocking
            ):
                self._pending_link_events = []
            else:
                del self._pending_link_events[:-MAX_PENDING_OBSERVATIONS]

    def _persist_sweep(
        self,
        store: Store,
        session_id: int,
        devices: list[Device],
        pending_obs: list[tuple[str, Advertisement]],
        pending_links: list[tuple[str | None, LinkEvent]],
        sweeps: int,
    ) -> None:
        """The sweep's storage work, run in a thread.

        Device serialization happens under the hub lock (the capture task is
        mutating those objects on the loop), but the lock is released before any
        SQLite call so a slow write never blocks ingest.
        """
        with self._lock:
            rows = store.device_rows(session_id, devices)
        try:
            if pending_obs:
                store.record_observations(session_id, pending_obs)
            if pending_links:
                store.record_link_events(session_id, pending_links)
        except Exception:
            # Hand the rows back so a transient store error costs a delay, not
            # the packets. The buffers are capped in _flush.
            self._pending_observations[:0] = pending_obs
            self._pending_link_events[:0] = pending_links
            raise
        store.snapshot_rows(rows)
        # Enforce the documented retention window. Without this the observations
        # table grows at packet rate forever and the "bounded by default"
        # promise is dead code. The live session is excluded: ageing it out
        # would cascade away the running capture's own rows.
        if sweeps % RETENTION_EVERY_SWEEPS == 0:
            store.enforce_retention(exclude_session=session_id)

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
                self._correlate()
                self._retire()
                self._refresh_alerts()
                # Everything below touches SQLite, which serializes on a lock
                # held across multi-second DELETEs and VACUUMs. Run it in a
                # thread: on a Pi with a large database the retention pass alone
                # blocks for seconds, and on the event loop that stalls ingest
                # (dropping packets at the queue) and every websocket.
                store, session_id = self.store, self.session_id
                if store is not None and session_id is not None:
                    devices = self.device_list()
                    pending_obs, self._pending_observations = self._pending_observations, []
                    pending_links, self._pending_link_events = self._pending_link_events, []
                    sweeps = self._sweeps
                    await asyncio.to_thread(
                        self._persist_sweep,
                        store,
                        session_id,
                        devices,
                        pending_obs,
                        pending_links,
                        sweeps,
                    )
                else:
                    self._flush()
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
                self._remap_acknowledged(key)
            self._broadcast("merged", {"removed": sorted(removed), "links": len(links)})

    def _remap_acknowledged(self, absorbed_key: str) -> None:
        """Carry alert dismissals onto the surviving key after a merge.

        Alert keys embed the device key ("separated:AA:BB:.."), and a merge
        keeps the elder's key. Without this the alert the user just dismissed is
        re-raised under the survivor's key on the very next sweep, and keeps
        coming back every ten seconds.
        """
        survivor_key = self._address_index.get(absorbed_key)
        if not survivor_key or survivor_key == absorbed_key:
            return
        for alert_key, level in list(self._acknowledged.items()):
            prefix, sep, device_key = alert_key.partition(":")
            if sep and device_key == absorbed_key:
                self._acknowledged.setdefault(f"{prefix}:{survivor_key}", level)

    def _index_device(self, device: Device) -> None:
        """Register every address this device is known by.

        ``_retire`` removes entries by walking ``addresses_seen``, so inserting
        only the currently observed address would leave rows behind pointing at
        a retired device — and a rotated address would then quietly start a new
        record instead of resolving to its cluster.
        """
        for addr in device.addresses_seen or [device.address]:
            self._address_index[addr] = device.key

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
        # sweep. A dismissal only silences the level it was made at: if the same
        # alert has since escalated — a tag that turns up in a second session is
        # promoted to ATTENTION — it is raised again, because that escalation is
        # the signal the tool exists to deliver.
        for alert in alerts:
            dismissed_at = self._acknowledged.get(alert.key)
            if dismissed_at is None:
                continue
            try:
                still_silenced = alert.level.rank <= AlertLevel(dismissed_at).rank
            except ValueError:
                still_silenced = True
            if still_silenced:
                alert.acknowledged = True
            else:
                del self._acknowledged[alert.key]
                if self.store is not None:
                    # record_alerts' upsert deliberately never touches the
                    # acknowledged column, so the stored dismissal has to be
                    # cleared explicitly or it would silence this alert again
                    # on the next restart.
                    with contextlib.suppress(Exception):
                        self.store.unacknowledge_alert(alert.key)
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
        level = AlertLevel.ATTENTION.value
        for alert in self.alerts:
            if alert.key == alert_key:
                alert.acknowledged = True
                level = alert.level.value
        self._acknowledged[alert_key] = level
        if self.store is not None:
            self.store.acknowledge_alert(alert_key, level)

    def after_purge(self) -> None:
        """Re-open storage after the user destroyed everything.

        ``Store.purge`` deletes every row of ``sessions``, but ``session_id``
        still points at the row that is now gone. With foreign keys on, the very
        next observation insert fails and ``_ingest`` exits — capture dies for
        the life of the process. Opening a fresh session immediately keeps the
        running capture writable. The in-memory dismissals go too: leaving them
        would silence alerts whose stored rows the user just deleted.
        """
        self._pending_observations.clear()
        self._pending_link_events.clear()
        self._acknowledged.clear()
        self.session_id = None
        if self.persist and self.store is not None:
            self.session_id = self.store.start_session(
                self.session_name,
                backend=self.backend.name,
                capabilities=self.backend.capabilities.to_dict(),
            )

    # -- views -------------------------------------------------------------

    @contextlib.contextmanager
    def reading(self) -> Any:
        """Hold the device lock across a multi-step read.

        Any caller that runs off the event loop — every sync FastAPI endpoint,
        which Starlette dispatches to a threadpool — must wrap its whole read in
        this, not just the container access. Device.to_dict(), exposure() and
        smoothed_rssi all walk deques and Counters that the capture task mutates
        per packet, so touching them outside the lock raises "deque mutated
        during iteration" under load.
        """
        with self._lock:
            yield

    def device_list(self) -> list[Device]:
        # Hold the lock across the sort as well as the copy: sorting reads
        # smoothed_rssi, which walks the rssi_history deque that the capture
        # task appends to on every packet.
        with self._lock:
            return sorted(
                self.devices.values(), key=lambda d: -(d.smoothed_rssi or -127)
            )

    def device_dicts(self) -> list[dict[str, Any]]:
        """Serialize every device, safely, from any thread.

        ``device_list`` hands back live Device objects, and ``to_dict`` iterates
        deques and Counters that the capture task mutates on the event loop —
        so serializing outside the lock raises "deque mutated during iteration"
        several times a minute in a busy room. Every reader that runs off the
        loop must go through here rather than mapping over ``device_list``.
        """
        with self._lock:
            return [d.to_dict() for d in self.device_list()]

    def backend_view(self) -> dict[str, Any]:
        """What the clients should believe about the radio.

        ``backend.describe()`` reports the backend's own status, which stays
        "running" after ``_ingest`` has died — so an error recorded there would
        be overwritten by the next sweep's snapshot and the dashboard would show
        a healthy capture that is not capturing. The hub's own status wins.
        """
        view = self.backend.describe()
        if self.backend_status.state == "error":
            view["status"] = self.backend_status.to_dict()
            view["running"] = False
        return view

    def snapshot(self, include_feed: bool = False) -> dict[str, Any]:
        with self._lock:
            devices = self.device_list()
            device_dicts = [d.to_dict() for d in devices]
            summary = describe_room(devices)
        payload: dict[str, Any] = {
            "devices": device_dicts,
            "stats": self.stats.to_dict(),
            "alerts": [a.to_dict() for a in self.alerts],
            "summary": summary,
            "exposure": self.exposure_summary(),
            "backend": self.backend_view(),
            "session_id": self.session_id,
        }
        if include_feed:
            payload["feed"] = list(self.feed)
            payload["link_feed"] = list(self.link_feed)
        return payload

    def exposure_summary(self) -> dict[str, Any]:
        scores = []
        bands: dict[str, int] = {}
        reasons: dict[str, int] = {}
        # exposure(), rotates_address and the tags Counter all read live state
        # the capture task mutates, so the lock has to cover every per-device
        # read here — not just the copy of the container. Reduce to plain
        # numbers inside the lock and release before building the payload.
        totals = dict.fromkeys(
            (
                "total",
                "rotating",
                "named",
                "plaintext_content",
                "trackers",
                "with_link_data",
                "encrypted_links",
                "plaintext_links",
            ),
            0,
        )
        with self._lock:
            for d in self.devices.values():
                exposure = d.exposure()
                scores.append(exposure.score)
                bands[exposure.band] = bands.get(exposure.band, 0) + 1
                for reason in exposure.reasons:
                    reasons[reason] = reasons.get(reason, 0) + 1
                totals["total"] += 1
                totals["rotating"] += 1 if d.rotates_address else 0
                totals["named"] += 1 if d.names else 0
                totals["plaintext_content"] += 1 if "plaintext_content" in d.tags else 0
                totals["trackers"] += 1 if d.is_tracker else 0
                totals["with_link_data"] += 1 if d.link_event_count else 0
                totals["encrypted_links"] += 1 if d.encrypted_link_seen else 0
                totals["plaintext_links"] += 1 if d.plaintext_link_seen else 0
        scores.sort()
        return {
            "total": totals["total"],
            "bands": bands,
            "rotating": totals["rotating"],
            "stable": totals["total"] - totals["rotating"],
            "named": totals["named"],
            "plaintext_content": totals["plaintext_content"],
            "trackers": totals["trackers"],
            "median_score": scores[len(scores) // 2] if scores else 0,
            "top_reasons": sorted(reasons.items(), key=lambda kv: -kv[1])[:8],
            "with_link_data": totals["with_link_data"],
            "encrypted_links": totals["encrypted_links"],
            "plaintext_links": totals["plaintext_links"],
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
