"""HTTP + WebSocket API, and the static web app.

The capture service is the product; the dashboard is one client of it. Every
view in the web app is built from these endpoints, and everything the web app
can do, the CLI and ``curl`` can do too.

Binding is localhost-only by default. ``--host 0.0.0.0`` is an explicit opt-in
for viewing from a phone or another machine on your LAN, and the service says
so loudly when you use it.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from importlib import resources
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from blemon import __version__
from blemon.capture.probe import PROBE_WARNING, is_allowed, probe
from blemon.decode import registered
from blemon.identity import explain_absence, registered_matchers
from blemon.service.hub import Hub
from blemon.store import devices_to_csv, devices_to_json, observations_to_csv, observations_to_json
from blemon.translate import describe_device


def web_asset_dir() -> Path | None:
    """The built dashboard bundled inside the package, if it was built."""
    try:
        path = Path(str(resources.files("blemon").joinpath("web")))
    except (ModuleNotFoundError, TypeError):
        return None
    return path if (path / "index.html").exists() else None


PLACEHOLDER_PAGE = """<!doctype html>
<meta charset="utf-8">
<title>ble-monitor</title>
<style>
  body { background:#080B10; color:#DCE4EE; font: 15px/1.6 ui-monospace, monospace;
         margin:0; display:grid; place-items:center; min-height:100vh; padding:24px; }
  main { max-width: 60ch; }
  h1 { font-size: 20px; letter-spacing:-.01em; }
  code { background:#151C26; padding:2px 6px; }
  a { color:#4CE0B3; }
</style>
<main>
  <h1>ble-monitor is running, but the dashboard was not built</h1>
  <p>The API is live and everything works — this is only the web bundle missing,
     which happens when running from a source checkout without building it.</p>
  <p>Build it with <code>npm --prefix web install &amp;&amp; npm --prefix web run build</code>,
     or use the CLI: <code>blemon scan</code>.</p>
  <p>API entry points: <a href="/api/status">/api/status</a> ·
     <a href="/api/devices">/api/devices</a> ·
     <a href="/api/capabilities">/api/capabilities</a> ·
     <a href="/docs">/docs</a></p>
</main>
"""


def create_app(hub: Hub, allow_probe: bool = True, allowlist_only: bool = True) -> FastAPI:
    app = FastAPI(
        title="ble-monitor",
        version=__version__,
        description=(
            "Local capture service for BLE advertising traffic. All data stays on this "
            "machine; nothing is uploaded anywhere."
        ),
    )
    app.state.hub = hub
    app.state.allow_probe = allow_probe
    app.state.allowlist_only = allowlist_only

    # -- meta --------------------------------------------------------------

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        return {
            "version": __version__,
            "now": time.time(),
            "stats": hub.stats.to_dict(),
            "backend": hub.backend.describe(),
            "backend_status": hub.backend_status.to_dict(),
            "session_id": hub.session_id,
            "device_count": len(hub.devices),
            "persisting": hub.persist,
            "probe_enabled": app.state.allow_probe,
            "probe_allowlist_only": app.state.allowlist_only,
        }

    @app.get("/api/capabilities")
    def capabilities() -> dict[str, Any]:
        caps = hub.backend.capabilities
        return {
            "backend": hub.backend.name,
            "capabilities": caps.to_dict(),
            "missing": caps.missing(),
            "decoders": registered(),
            "matchers": registered_matchers(),
            "note": (
                "This is what the current setup can and cannot see. Nothing in the "
                "interface will imply a capability that is not listed here as true."
            ),
        }

    # -- devices -----------------------------------------------------------

    @app.get("/api/devices")
    def devices(
        category: str | None = None,
        tracker_only: bool = False,
        search: str | None = None,
        min_rssi: int | None = None,
    ) -> dict[str, Any]:
        out = []
        for device in hub.device_list():
            if category and device.category.value != category:
                continue
            if tracker_only and not device.is_tracker:
                continue
            if min_rssi is not None and (device.smoothed_rssi or -127) < min_rssi:
                continue
            if search:
                needle = search.lower()
                haystack = " ".join(
                    [device.display_name, device.address, *device.names, *device.service_uuids]
                ).lower()
                if needle not in haystack:
                    continue
            out.append(device.to_dict())
        return {"devices": out, "count": len(out), "summary": hub.snapshot()["summary"]}

    @app.get("/api/devices/{key}")
    def device_detail(key: str) -> dict[str, Any]:
        device = hub.devices.get(key)
        if device is None:
            raise HTTPException(404, f"No live device with key {key!r}")
        payload = device.to_dict(include_decode=True)
        payload["english"] = describe_device(device)
        payload["continuity_note"] = explain_absence(device)
        if hub.store is not None:
            payload["history"] = hub.store.device_history(key)
            payload["link_events"] = (
                hub.store.link_events(hub.session_id, key) if hub.session_id else []
            )
        return payload

    @app.post("/api/devices/{key}/label")
    async def set_label(key: str, request: Request) -> dict[str, Any]:
        body = await request.json()
        device = hub.set_label(
            key,
            label=body.get("label"),
            is_mine=body.get("is_mine"),
            notes=body.get("notes"),
        )
        if device is None:
            return {"ok": True, "stored": True, "live": False}
        return {"ok": True, "stored": True, "live": True, "device": device.to_dict()}

    # -- the two hero views ------------------------------------------------

    @app.get("/api/radar")
    def radar() -> dict[str, Any]:
        devices = hub.device_list()
        return {
            "devices": [
                {
                    "key": d.key,
                    "label": d.display_name,
                    "category": d.category.value,
                    "angle": d.radar_angle,
                    "rssi": d.smoothed_rssi,
                    "proximity": d.proximity.value,
                    "advertising_rate": round(d.advertising_rate, 2),
                    "is_tracker": d.is_tracker,
                    "rotating": d.rotates_address,
                    "exposure": d.exposure().score,
                    "last_seen": d.last_seen,
                    "first_seen": d.first_seen,
                    "is_guess": d.user_label is None,
                }
                for d in devices
            ],
            "honesty": {
                "angle": (
                    "Bluetooth gives no direction information whatsoever. Each device's "
                    "angle is derived from a hash of its identity so it stays in the same "
                    "place frame to frame. Only distance from the centre means anything."
                ),
                "distance": (
                    "Distance is a coarse band derived from signal strength. Converting "
                    "signal strength to metres is unreliable enough to be misleading, so "
                    "no metre figure is shown anywhere."
                ),
            },
        }

    @app.get("/api/city")
    def city() -> dict[str, Any]:
        devices = hub.device_list()
        max_rate = max((d.advertising_rate for d in devices), default=1.0) or 1.0
        max_duration = max((d.duration for d in devices), default=1.0) or 1.0
        return {
            "buildings": [
                {
                    "key": d.key,
                    "label": d.display_name,
                    "category": d.category.value,
                    "district": d.category.value,
                    "vendor": (d.company_names[0] if d.company_names else None),
                    # Deterministic lot: the same device lands in the same place
                    # every session, so a place has a recognisable skyline.
                    "lot": d.stable_hash(),
                    "height": round(min(1.0, d.advertising_rate / max_rate), 4),
                    "footprint": round(min(1.0, d.duration / max_duration), 4),
                    "proximity": d.proximity.value,
                    "rssi": d.smoothed_rssi,
                    "lit": time.time() - d.last_seen < 5.0,
                    "last_seen": d.last_seen,
                    # Glass = broadcasting in the clear, opaque = shuttered.
                    "material": "glass" if d.exposure().score >= 45 else "opaque",
                    "exposure": d.exposure().score,
                    "is_tracker": d.is_tracker,
                    "rotating": d.rotates_address,
                    "packet_count": d.packet_count,
                    "advertising_rate": round(d.advertising_rate, 2),
                }
                for d in devices
            ],
            "legend": {
                "height": "advertising rate — chatty devices are skyscrapers",
                "footprint": "how long it has been observed — persistent devices become landmarks",
                "district": "category and manufacturer",
                "distance": "proximity band",
                "lit": "advertised within the last five seconds",
                "material": "glass means it broadcasts readable identity or content; "
                "opaque means it rotates and says little",
                "lot": "derived from a hash of the device's identity, so the same device "
                "occupies the same plot every time you come back",
            },
        }

    # -- supporting views --------------------------------------------------

    @app.get("/api/feed")
    def feed(limit: int = Query(200, le=600)) -> dict[str, Any]:
        return {"packets": list(hub.feed)[-limit:], "link_events": list(hub.link_feed)[-limit:]}

    @app.get("/api/timeline")
    def timeline(buckets: int = Query(60, ge=10, le=240)) -> dict[str, Any]:
        return hub.timeline(buckets)

    @app.get("/api/exposure")
    def exposure() -> dict[str, Any]:
        summary = hub.exposure_summary()
        summary["devices"] = [
            {
                "key": d.key,
                "label": d.display_name,
                "category": d.category.value,
                **d.exposure().to_dict(),
            }
            for d in sorted(hub.device_list(), key=lambda x: -x.exposure().score)
        ]
        return summary

    @app.get("/api/alerts")
    def alerts() -> dict[str, Any]:
        return {"alerts": [a.to_dict() for a in hub.alerts]}

    @app.post("/api/alerts/{key}/acknowledge")
    def acknowledge(key: str) -> dict[str, Any]:
        hub.acknowledge_alert(key)
        return {"ok": True}

    @app.get("/api/summary")
    def summary() -> dict[str, Any]:
        return hub.snapshot(include_feed=False)

    # -- sniffer control ---------------------------------------------------

    @app.post("/api/follow/{key}")
    async def follow(key: str) -> dict[str, Any]:
        device = hub.devices.get(key)
        address = device.address if device else key
        if not hub.backend.capabilities.connection_following:
            raise HTTPException(
                400,
                "This capture backend cannot follow connections. That needs sniffer "
                "hardware — see the capability panel.",
            )
        ok = await hub.backend.follow(address)
        return {
            "ok": ok,
            "address": address,
            "note": (
                "The sniffer is now aimed at this device. It follows one connection at a "
                "time, so broad advertising capture is reduced while it is pointed here."
            ),
        }

    @app.post("/api/unfollow")
    async def unfollow() -> dict[str, Any]:
        await hub.backend.unfollow()
        return {"ok": True}

    # -- active probing ----------------------------------------------------

    @app.post("/api/devices/{key}/probe")
    async def probe_device(key: str) -> dict[str, Any]:
        if not app.state.allow_probe:
            raise HTTPException(
                403,
                "Active probing is disabled on this service. Start it with "
                "`blemon serve --allow-probe` if you want it.",
            )
        device = hub.devices.get(key)
        address = device.address if device else key
        mine = {d.address for d in hub.devices.values() if d.is_mine} | {
            k for k, v in hub._labels.items() if v.get("is_mine")
        }
        ok, why = is_allowed(address, app.state.allowlist_only, mine)
        if not ok:
            raise HTTPException(403, why)
        result = await probe(address)
        if device is not None and result.success:
            from blemon.identity import identify

            device.identification = identify(device)
            extra = result.to_guesses()
            if extra and device.identification:
                best = device.identification.best
                if best:
                    device.identification.runners_up.insert(0, best)
                device.identification.best = extra[0]
        return result.to_dict()

    @app.get("/api/probe/policy")
    def probe_policy() -> dict[str, Any]:
        return {
            "enabled": app.state.allow_probe,
            "allowlist_only": app.state.allowlist_only,
            "warning": PROBE_WARNING,
            "allowlisted": sorted(
                {d.address for d in hub.devices.values() if d.is_mine}
            ),
        }

    # -- storage, sessions, export ----------------------------------------

    @app.get("/api/sessions")
    def sessions() -> dict[str, Any]:
        if hub.store is None:
            return {"sessions": [], "note": "This service is running without persistence."}
        return {"sessions": hub.store.sessions()}

    @app.get("/api/stored")
    def stored() -> dict[str, Any]:
        if hub.store is None:
            return {"note": "Nothing is being stored — this service is running in memory only."}
        return hub.store.what_is_stored()

    @app.post("/api/purge")
    async def purge(request: Request) -> dict[str, Any]:
        if hub.store is None:
            return {"ok": True, "note": "Nothing was stored."}
        body = {}
        with contextlib.suppress(Exception):
            body = await request.json()
        hub.store.purge(keep_labels=body.get("keep_labels", True))
        return {"ok": True, "stored": hub.store.what_is_stored()}

    @app.get("/api/export/devices.json")
    def export_devices_json(redact: bool = False) -> Response:
        rows = [{"snapshot": d.to_dict()} for d in hub.device_list()]
        return Response(
            devices_to_json(rows, redact=redact, metadata={"backend": hub.backend.name}),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=ble-devices.json"},
        )

    @app.get("/api/export/devices.csv")
    def export_devices_csv(redact: bool = False) -> Response:
        rows = [{"snapshot": d.to_dict()} for d in hub.device_list()]
        return PlainTextResponse(
            devices_to_csv(rows, redact=redact),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=ble-devices.csv"},
        )

    @app.get("/api/export/observations.{fmt}")
    def export_observations(fmt: str, redact: bool = False, limit: int = 50_000) -> Response:
        if hub.store is None or hub.session_id is None:
            raise HTTPException(400, "No recorded session to export from.")
        rows = hub.store.observations(session_id=hub.session_id, limit=limit)
        if fmt == "json":
            return Response(
                observations_to_json(rows, redact=redact),
                media_type="application/json",
                headers={"Content-Disposition": "attachment; filename=ble-observations.json"},
            )
        if fmt == "csv":
            return PlainTextResponse(
                observations_to_csv(rows, redact=redact),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=ble-observations.csv"},
            )
        raise HTTPException(400, "Format must be json or csv. For PCAP use `blemon export`.")

    # -- live stream -------------------------------------------------------

    @app.websocket("/ws")
    async def websocket(ws: WebSocket) -> None:
        await ws.accept()
        queue = hub.subscribe()
        try:
            await ws.send_json({"type": "snapshot", **hub.snapshot(include_feed=True)})
            while True:
                message = await queue.get()
                await ws.send_json(message)
        except WebSocketDisconnect:
            pass
        except (asyncio.CancelledError, RuntimeError):
            pass
        finally:
            hub.unsubscribe(queue)

    # -- the dashboard -----------------------------------------------------

    assets = web_asset_dir()
    if assets is not None:
        app.mount("/assets", StaticFiles(directory=str(assets / "assets")), name="assets")

        @app.get("/", response_class=HTMLResponse)
        def index() -> HTMLResponse:
            return HTMLResponse((assets / "index.html").read_text(encoding="utf-8"))

        @app.get("/{path:path}", response_class=HTMLResponse)
        def spa(path: str) -> HTMLResponse:
            # Single-page app: unknown paths render the shell, not a 404.
            if path.startswith("api/"):
                return JSONResponse({"detail": "Not found"}, status_code=404)
            candidate = assets / path
            if path and candidate.is_file():
                return HTMLResponse(candidate.read_text(encoding="utf-8"))
            return HTMLResponse((assets / "index.html").read_text(encoding="utf-8"))
    else:

        @app.get("/", response_class=HTMLResponse)
        def placeholder() -> HTMLResponse:
            return HTMLResponse(PLACEHOLDER_PAGE)

    return app
