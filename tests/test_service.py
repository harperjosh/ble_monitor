"""Capture, hub, API and CLI tests — all against the synthetic backend."""

from __future__ import annotations

import asyncio
import json
import random
import time

import pytest
from fastapi.testclient import TestClient

from blemon.capture import CaptureError, autoselect, available_backends, create
from blemon.capture.base import BackendStatus
from blemon.capture.probe import PROBE_WARNING, is_allowed
from blemon.fixtures import advertisement_from, default_population
from blemon.models import Advertisement
from blemon.service import Hub, create_app
from blemon.store import Store


class TestBackendRegistry:
    def test_synthetic_is_always_available_so_the_tool_is_never_blank(self):
        assert available_backends()["synthetic"] == ""

    def test_unavailable_backends_explain_themselves(self):
        for name, reason in available_backends().items():
            if reason:
                assert len(reason) > 10, f"{name} gives a useless reason: {reason!r}"

    def test_autoselect_always_returns_something(self):
        assert autoselect() is not None

    def test_unknown_backend_raises_with_a_remedy(self):
        with pytest.raises(CaptureError) as exc:
            create("does-not-exist")
        assert exc.value.remedy


class TestCapabilities:
    def test_every_backend_declares_capabilities_and_caveats(self):
        for name in ("synthetic", "hci", "bleak", "sniffle", "nrf"):
            caps = create(name).capabilities
            assert caps.name and caps.description
            assert caps.caveats, f"{name} declares no caveats"

    def test_no_host_adapter_backend_claims_connection_following(self):
        """A host adapter cannot hop the data channels. Claiming otherwise
        would be the single most misleading thing this tool could do."""
        for name in ("synthetic", "hci", "bleak"):
            assert create(name).capabilities.connection_following is False

    def test_sniffer_backends_do_claim_connection_following(self):
        for name in ("sniffle", "nrf"):
            assert create(name).capabilities.connection_following is True

    def test_nothing_claims_it_can_transmit(self):
        """Receive-only is the default posture. Probing is a separate path."""
        for name in ("synthetic", "hci", "bleak", "sniffle", "nrf"):
            assert create(name).capabilities.can_transmit is False

    def test_missing_capabilities_are_phrased_for_a_human(self):
        missing = create("synthetic").capabilities.missing()
        assert any("connection following" in m for m in missing)


class TestSyntheticBackend:
    async def test_it_produces_decodable_traffic(self):
        backend = create("synthetic", seed=3)
        await backend.start()
        seen, addresses = 0, set()
        async for event in backend.stream():
            if isinstance(event, BackendStatus):
                continue
            assert isinstance(event, Advertisement)
            assert event.raw and event.rssi is not None
            addresses.add(event.address)
            seen += 1
            if seen >= 120:
                break
        await backend.stop()
        assert seen == 120
        assert len(addresses) >= 8

    async def test_it_is_labelled_as_not_a_radio(self):
        caps = create("synthetic").capabilities
        assert any("not a radio" in c for c in caps.caveats)


def populate(
    hub: Hub,
    seconds: float = 240.0,
    step: float = 0.25,
    seed: int = 17,
    rotate_every: float | None = 45.0,
) -> Hub:
    """Drive a hub through a stretch of simulated air, synchronously.

    Feeding the hub directly rather than running the capture loop keeps these
    tests deterministic and instant: no sleeping, no scheduler, and the same
    device population every run.

    ``rotate_every`` compresses the 15-minute address-rotation period so the
    correlation path is exercised without simulating a quarter of an hour.
    """
    rng = random.Random(seed)
    population = default_population()
    if rotate_every is not None:
        for device in population:
            if device.rotate_every is not None:
                device.rotate_every = rotate_every
    now = time.time() - seconds
    elapsed = 0.0
    while elapsed < seconds:
        for device in population:
            if not (device.present_from <= elapsed <= device.present_until):
                continue
            if rng.random() > step / device.interval:
                continue
            adv = advertisement_from(device, elapsed, rng)
            adv.timestamp = now + elapsed
            hub.ingest(adv)
        elapsed += step
    hub.refresh()
    return hub


@pytest.fixture(scope="module")
def hub(tmp_path_factory):
    store = Store(tmp_path_factory.mktemp("api") / "api.db")
    h = Hub(create("synthetic", seed=17), store=store, session_name="test")
    h.session_id = store.start_session("test", backend="synthetic",
                                       capabilities=h.backend.capabilities.to_dict())
    populate(h)
    yield h
    store.close()


@pytest.fixture(scope="module")
def client(hub):
    return TestClient(create_app(hub, allow_probe=False))


class TestHub:
    def test_it_accumulates_devices_and_identifies_them(self, hub):
        assert len(hub.devices) >= 8
        assert hub.stats.packets > 200
        assert all(d.identification for d in hub.devices.values())

    def test_the_packet_feed_carries_plain_english(self, hub):
        assert [r for r in hub.feed if r["english"]]

    def test_it_persists_to_the_store(self, hub):
        assert hub.store.what_is_stored()["counts"]["observations"] > 0

    def test_it_correlates_rotating_addresses(self, hub):
        merged = [d for d in hub.devices.values() if len(d.addresses_seen) > 1]
        assert merged, "no MAC-rotation correlation happened over four minutes"
        for device in merged:
            assert device.continuity_confidence < 1.0  # never a certainty
            assert device.continuity_evidence

    def test_a_slow_subscriber_is_dropped_from_rather_than_stalling_the_hub(self, hub):
        queue = hub.subscribe(maxsize=1)
        for _ in range(50):
            hub._broadcast("packet", {"packet": {}})
        assert queue.qsize() <= 1  # the queue never grew unbounded
        hub.unsubscribe(queue)

    async def test_the_live_loop_runs_and_stops_cleanly(self, tmp_path):
        h = Hub(create("synthetic", seed=5), store=None, persist=False)
        await h.start()
        await asyncio.sleep(1.5)
        assert h.stats.packets > 0
        await h.stop()
        assert not h._tasks


class TestApi:
    @pytest.mark.parametrize(
        "path",
        ["/api/status", "/api/capabilities", "/api/devices", "/api/radar", "/api/city",
         "/api/exposure", "/api/timeline", "/api/feed", "/api/alerts", "/api/summary",
         "/api/sessions", "/api/stored", "/api/probe/policy"],
    )
    def test_endpoint_answers(self, client, path):
        response = client.get(path)
        assert response.status_code == 200, response.text
        assert response.json() is not None

    def test_radar_states_that_angle_is_meaningless(self, client):
        honesty = client.get("/api/radar").json()["honesty"]
        assert "no direction" in honesty["angle"]
        assert "metre" in honesty["distance"]

    def test_radar_never_returns_a_distance_in_metres(self, client):
        for device in client.get("/api/radar").json()["devices"]:
            assert "distance" not in device and "metres" not in device
            assert device["proximity"] in {"immediate", "near", "far", "distant"}

    def test_city_lots_are_deterministic_across_calls(self, client):
        first = {b["key"]: b["lot"] for b in client.get("/api/city").json()["buildings"]}
        second = {b["key"]: b["lot"] for b in client.get("/api/city").json()["buildings"]}
        shared = set(first) & set(second)
        assert shared
        assert all(first[k] == second[k] for k in shared)

    def test_city_legend_explains_every_encoding(self, client):
        legend = client.get("/api/city").json()["legend"]
        assert {"height", "footprint", "district", "distance", "lit", "material", "lot"} <= set(legend)

    def test_device_detail_includes_the_reasoning(self, client):
        key = client.get("/api/devices").json()["devices"][0]["key"]
        detail = client.get(f"/api/devices/{key}").json()
        assert detail["english"]
        assert detail["continuity_note"]
        assert "byte_profiles" in detail
        ident = detail["identification"]
        if ident and ident["best"]:
            assert ident["best"]["evidence"]

    def test_a_guess_is_always_flagged_as_a_guess(self, client):
        for device in client.get("/api/devices").json()["devices"]:
            ident = device["identification"]
            if ident and ident["best"]:
                assert ident["is_guess"] is (device["user_label"] is None)
                assert ident["best"]["confidence"] in {"certain", "high", "medium", "low"}

    def test_missing_device_is_a_404(self, client):
        assert client.get("/api/devices/NO:SUCH:DEVICE").status_code == 404

    def test_labelling_persists_and_overrides_the_guess(self, client):
        key = client.get("/api/devices").json()["devices"][0]["key"]
        response = client.post(f"/api/devices/{key}/label",
                               json={"label": "My thing", "is_mine": True})
        assert response.json()["device"]["display_name"] == "My thing"
        assert client.get(f"/api/devices/{key}").json()["identification"]["is_guess"] is False

    def test_following_is_refused_when_the_hardware_cannot_do_it(self, client):
        key = client.get("/api/devices").json()["devices"][0]["key"]
        response = client.post(f"/api/follow/{key}")
        assert response.status_code == 400
        assert "sniffer" in response.json()["detail"]

    def test_probing_is_refused_when_disabled(self, client):
        key = client.get("/api/devices").json()["devices"][0]["key"]
        assert client.post(f"/api/devices/{key}/probe").status_code == 403

    def test_exports(self, client):
        assert client.get("/api/export/devices.json").status_code == 200
        csv_text = client.get("/api/export/devices.csv").text
        assert csv_text.startswith("key,address")
        redacted = client.get("/api/export/devices.json?redact=true").json()
        assert redacted["redacted"] is True

    def test_stored_view_says_nothing_leaves_the_machine(self, client):
        assert "uploaded anywhere" in client.get("/api/stored").json()["note"]

    def test_websocket_opens_with_a_full_snapshot(self, client):
        with client.websocket_connect("/ws") as ws:
            message = ws.receive_json()
        assert message["type"] == "snapshot"
        assert message["devices"] and "backend" in message and "summary" in message

    def test_capabilities_endpoint_lists_decoders_and_matchers(self, client):
        body = client.get("/api/capabilities").json()
        assert body["decoders"]["manufacturer"] and body["decoders"]["service_data"]
        assert body["matchers"]


class TestProbePolicy:
    def test_allowlist_blocks_devices_that_are_not_yours(self):
        ok, why = is_allowed("AA:BB:CC:DD:EE:FF", allowlist_only=True, mine=set())
        assert not ok and "not marked as your own" in why

    def test_allowlist_permits_your_own_hardware(self):
        ok, _ = is_allowed("AA:BB:CC:DD:EE:FF", True, {"aa:bb:cc:dd:ee:ff"})
        assert ok

    def test_without_the_allowlist_anything_is_permitted(self):
        assert is_allowed("AA:BB", allowlist_only=False, mine=set())[0]

    def test_the_warning_says_the_target_can_see_it(self):
        assert "will see it" in PROBE_WARNING


class TestCli:
    def test_doctor_json_is_machine_readable(self, capsys):
        from blemon.cli.main import main

        assert main(["doctor", "--json"]) in (0, 1)
        report = json.loads(capsys.readouterr().out)
        assert report["worst"] in {"ok", "warn", "fail", "info"}
        assert report["findings"]
        for finding in report["findings"]:
            if finding["level"] in ("warn", "fail"):
                assert finding["remedy"], f"{finding['title']} has no remedy"

    def test_doctor_renders_for_a_human(self, capsys):
        from blemon.cli.main import main

        main(["doctor"])
        out = capsys.readouterr().out
        assert "capability" in out.lower() or "can see" in out.lower()

    def test_scan_json_streams_lines(self, tmp_path, capsys):
        from blemon.cli.main import main

        assert main(["scan", "--backend", "synthetic", "--db", str(tmp_path / "s.db"),
                     "--seconds", "2", "--json"]) == 0
        lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
        assert lines
        for line in lines[:20]:
            assert json.loads(line)["type"] in {"packet", "devices", "alerts"}

    def test_devices_and_sessions_query_the_store(self, tmp_path, capsys):
        from blemon.cli.main import main

        db = str(tmp_path / "s.db")
        main(["scan", "--backend", "synthetic", "--db", db, "--seconds", "3", "--json"])
        capsys.readouterr()
        assert main(["devices", "--db", db, "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["count"] > 0
        assert main(["sessions", "--db", db, "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["sessions"]

    def test_export_pcap_from_the_cli(self, tmp_path, capsys):
        from blemon.cli.main import main

        db = str(tmp_path / "s.db")
        out = tmp_path / "out.pcap"
        main(["scan", "--backend", "synthetic", "--db", db, "--seconds", "3", "--json"])
        capsys.readouterr()
        assert main(["export", "--db", db, "--format", "pcap", "-o", str(out)]) == 0
        assert out.stat().st_size > 24

    def test_no_arguments_prints_help_rather_than_failing(self, capsys):
        from blemon.cli.main import main

        assert main([]) == 0
        assert "blemon doctor" in capsys.readouterr().out
