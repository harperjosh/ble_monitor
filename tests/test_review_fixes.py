"""Regression tests for defects found in code review.

Each test here corresponds to a specific bug fixed after the first review pass,
and fails against the code as it was before the fix.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from blemon import fixtures as fx
from blemon.capture import CaptureError, create
from blemon.capture.bleak_backend import _resolve_address_type
from blemon.capture.llparse import parse_adv_pdu
from blemon.capture.nrf_sniffer import SlipDecoder, slip_encode
from blemon.decode import parse
from blemon.decode.assigned import normalize_uuid, service_name
from blemon.device import Device
from blemon.identity import evaluate_all, identify
from blemon.models import AddressType, Advertisement, classify_address
from blemon.service import Hub, create_app
from blemon.store import Store, observations_to_json, write_pcap
from blemon.store.export import redact_raw_payload


def adv(raw: bytes, address="AA:BB:CC:DD:EE:FF", random=False, rssi=-55):
    return Advertisement(address=address, raw=raw, rssi=rssi,
                         address_type=classify_address(address, random))


def decoding(parsed, protocol):
    for d in parsed.decodings:
        if d.protocol == protocol:
            return d
    raise AssertionError(f"{protocol} not decoded: {sorted(d.protocol for d in parsed.decodings)}")


class _RecordingSerial:
    """Stands in for a pyserial port so command framing can be inspected."""

    def __init__(self):
        self.written = b""

    def write(self, data: bytes) -> None:
        self.written += data

    def follow_type_byte(self) -> int:
        """The address-type byte of the REQ_FOLLOW payload just written.

        Frame layout: SLIP-encoded (header[6] + payload), and the follow payload
        is addr[6] + addr_type[1] + two flag bytes.
        """
        frames = SlipDecoder().feed(self.written)
        assert frames, "no SLIP frame was written"
        return frames[-1][6 + 6]


# ---------------------------------------------------------------------------
# Decode correctness
# ---------------------------------------------------------------------------


class TestDecodeFixes:
    def test_normalize_uuid_collapses_the_32bit_base_form(self):
        assert normalize_uuid("0000FEAA") == "FEAA"
        assert normalize_uuid("0000180D-0000-1000-8000-00805F9B34FB") == "180D"
        assert normalize_uuid("FEAA") == "FEAA"

    def test_eddystone_via_32bit_service_data_still_decodes(self):
        # AD type 0x20 carries a 32-bit UUID; the body must still reach the
        # decoder registered under the 16-bit key "FEAA".
        body = bytes([0x10, 0xF6, 0x03]) + b"example" + bytes([0x07])
        raw = fx.payload(bytes([len(body) + 5, 0x20]) + b"\xaa\xfe\x00\x00" + body)
        assert decoding(parse(adv(raw)), "eddystone_url")
        assert service_name("0000FEAA") and "Eddystone" in service_name("0000FEAA")

    def test_govee_temperature_is_exact_at_high_humidity(self):
        # 21.0C / 60% packs to 210600; the old /10000 rounded it to 21.1.
        raw = fx.payload(fx.flags(), fx.govee(temperature=21.0, humidity=60.0, battery=90))
        d = decoding(parse(adv(raw)), "govee")
        temp = next(f.value for f in d.fields if f.name == "temperature_c")
        hum = next(f.value for f in d.fields if f.name == "humidity_percent")
        assert temp == pytest.approx(21.0)
        assert hum == pytest.approx(60.0)

    def test_aux_ptr_phy_is_read_from_the_correct_bits(self):
        # Extended header: flags byte with AuxPtr bit (0x10) set, then a 3-byte
        # AuxPtr whose top 3 bits of byte 2 encode PHY=2 (Coded), while the low
        # bits (the offset) are non-zero to catch the old >>1 reading.
        aux_ptr = bytes([0x25, 0x00, (0b010 << 5) | 0x1F])
        # ext-header length covers the flags byte (1) + the AuxPtr (3) = 4.
        payload = bytes([0x04, 0x10]) + aux_ptr  # ext_len, flags(AuxPtr bit), auxptr
        pdu = bytes([0x07, len(payload)]) + payload  # ADV_EXT_IND header
        parsed = parse_adv_pdu(pdu)
        assert parsed is not None and parsed.aux_phy == "Coded"

    def test_apple_find_my_separated_sets_the_tracker_tag(self):
        d = decoding(parse(adv(fx.payload(fx.find_my(separated=True)))), "apple_find_my")
        assert "separated_tracker" in d.tags
        # …and the nearby (owner-present) form does not.
        near = decoding(parse(adv(fx.payload(fx.find_my(separated=False)))), "apple_find_my")
        assert "separated_tracker" not in near.tags

    def test_xiaomi_mho_c_name_matches(self):
        device = Device(key="x", address="x")
        for _ in range(4):
            device.observe(parse(adv(fx.payload(fx.complete_name("MHO-C303")))))
        ident = identify(device)
        labels = [ident.best.label, *(g.label for g in ident.runners_up)] if ident.best else []
        assert any("Xiaomi" in label for label in labels)

    def test_pvvx_environmental_battery_and_mac(self):
        # pvvx custom 0x181A, the full 15-byte frame the firmware actually
        # sends: MAC(LE) + temp + hum + battery_mv + battery_pct + count + flags.
        import struct

        mac = bytes.fromhex("A4C1381122FF")  # stored low-byte-first
        body = (
            mac
            + struct.pack("<h", 2134)  # 21.34 C
            + struct.pack("<H", 4850)  # 48.5 %
            + struct.pack("<H", 2977)  # battery mV
            + bytes([93])  # battery %
            + bytes([7, 0])  # counter, flags
        )
        raw = fx.payload(fx.service_data16(0x181A, body))
        d = decoding(parse(adv(raw, address="FF:22:11:38:C1:A4")), "environmental_sensing")
        battery = next(f.value for f in d.fields if f.name == "battery_percent")
        mv = next(f.value for f in d.fields if f.name == "battery_mv")
        addr = next(f.value for f in d.fields if f.name == "device_address")
        assert battery == 93
        assert mv == 2977
        assert addr == "FF:22:11:38:C1:A4"  # reversed for display

    def test_atc1441_environmental_is_not_read_as_pvvx(self):
        # ATC1441 shares 0x181A but stores the MAC big-endian and packs its
        # fields differently. Decoding it with the pvvx layout yields a
        # byte-reversed address and nonsense readings that still look plausible.
        import struct

        body = (
            bytes.fromhex("A4C1381122FF")  # MAC, big-endian
            + struct.pack(">h", 213)  # 21.3 C
            + bytes([48])  # 48 % humidity
            + bytes([93])  # 93 % battery
            + struct.pack(">H", 2977)  # battery mV
            + bytes([7])  # counter
        )
        raw = fx.payload(fx.service_data16(0x181A, body))
        d = decoding(parse(adv(raw, address="A4:C1:38:11:22:FF")), "environmental_sensing")
        value = {f.name: f.value for f in d.fields}
        assert value["device_address"] == "A4:C1:38:11:22:FF"  # not reversed
        assert value["temperature_c"] == 21.3
        assert value["humidity_percent"] == 48
        assert value["battery_percent"] == 93
        assert value["battery_mv"] == 2977


# ---------------------------------------------------------------------------
# Capture-layer fixes
# ---------------------------------------------------------------------------


class TestCaptureFixes:
    def test_nrf_slip_roundtrips_the_special_bytes(self):
        # A payload containing every framing byte must survive encode->decode.
        payload = bytes([0xAB, 0xBC, 0xCD, 0x00, 0xFF, 0xAB])
        frames = SlipDecoder().feed(slip_encode(payload))
        assert frames == [payload]

    def test_bleak_address_type_uses_bluez_details_not_bit_guessing(self):
        class Dev:
            def __init__(self, at):
                self.details = {"props": {"AddressType": at}} if at else {}

        # A public MAC whose top bits look "random" must still classify public.
        assert _resolve_address_type(Dev("public"), "3C:9C:0F:44:21:AB", False) is AddressType.PUBLIC
        assert (
            _resolve_address_type(Dev("random"), "5E:11:A3:7C:90:22", False)
            is AddressType.RESOLVABLE_PRIVATE
        )
        # Unknown type is reported as UNKNOWN, not guessed (so it is not fed to
        # continuity as rotating nor scored as deliberately private).
        assert _resolve_address_type(Dev(None), "3C:9C:0F:44:21:AB", False) is AddressType.UNKNOWN
        assert _resolve_address_type(Dev(None), "AA:BB:CC:DD:EE:FF", True) is AddressType.OPAQUE

    def test_replay_without_a_session_id_raises_captureerror(self):
        with pytest.raises(CaptureError):
            create("replay")

    def test_bleak_defaults_to_passive_scan_mode(self):
        assert create("bleak")._scan_mode == "passive"


# ---------------------------------------------------------------------------
# Continuity / device merge
# ---------------------------------------------------------------------------


class TestMergeFixes:
    def test_absorb_preserves_is_mine_and_label(self):
        elder = Device(key="A", address="A")
        younger = Device(key="B", address="B", is_mine=True, user_label="My earbuds")
        younger.encrypted_link_seen = True
        elder.absorb(younger, 0.8, ["evidence"])
        assert elder.is_mine is True
        assert elder.user_label == "My earbuds"
        assert elder.encrypted_link_seen is True

    def test_a_merged_own_device_does_not_resurrect_tracker_alerts(self):
        # A separated tracker the user marked as theirs, merged into an elder
        # record, must stay silenced after the merge.
        elder = Device(key="A", address="A", first_seen=time.time() - 3600)
        younger = Device(key="B", address="B", is_mine=True)
        for _ in range(5):
            younger.observe(parse(adv(fx.payload(fx.find_my(separated=True)),
                                      address="B", random=True)))
        elder.absorb(younger, 0.8, ["e"])
        elder.identification = identify(elder)
        assert evaluate_all([elder]) == []


# ---------------------------------------------------------------------------
# Storage / redaction
# ---------------------------------------------------------------------------


class TestRedactionFixes:
    def test_redact_raw_payload_blanks_the_local_name(self):
        raw = fx.payload(fx.flags(), fx.complete_name("Sam's iPhone"), fx.apple_nearby_info())
        redacted = redact_raw_payload(raw)
        assert b"Sam" not in redacted
        # The framing and other structures survive.
        assert len(redacted) == len(raw)
        assert redacted[:3] == raw[:3]  # flags structure intact

    def test_redacted_observation_export_has_no_name_in_the_raw_hex(self):
        raw = fx.payload(fx.complete_name("Sam's iPhone"))
        rows = [{"ts": 1.0, "address": "AA:BB", "device_key": "AA:BB", "rssi": -50,
                 "channel": 37, "pdu_type": "ADV_IND", "phy": "1M", "scan_rsp": 0,
                 "source": "t", "raw": raw}]
        out = observations_to_json(rows, redact=True)
        assert "Sam" not in out
        assert b"Sam's iPhone".hex() not in out

    def test_redacted_pcap_has_no_name_bytes(self, tmp_path):
        a = adv(fx.payload(fx.complete_name("Sam's iPhone")))
        path = tmp_path / "c.pcap"
        write_pcap(str(path), [a], redact=True)
        assert b"Sam's iPhone" not in path.read_bytes()

    def test_link_events_read_path_uses_timestamp_not_ts(self, tmp_path):
        from blemon.models import LinkEvent

        store = Store(tmp_path / "t.db")
        sid = store.start_session("s")
        store.record_link_events(sid, [("AA:BB", LinkEvent(timestamp=123.0, kind="gatt",
                                                           summary="read"))])
        rows = store.link_events(sid)
        assert rows and rows[0]["timestamp"] == 123.0 and "ts" not in rows[0]
        store.close()

    def test_search_wildcards_are_escaped(self, tmp_path):
        store = Store(tmp_path / "t.db")
        sid = store.start_session("s")
        for name in ("AC-100%-unit", "AC-1000-unit"):
            d = Device(key=name, address=name)
            d.observe(parse(adv(fx.payload(fx.flags()))))
            d.user_label = name
            store.snapshot_devices(sid, [d])
        # "100%" must match the literal "%", not act as a LIKE wildcard that
        # also matches "AC-1000-unit".
        hits = store.devices(search="100%")
        assert len(hits) == 1 and hits[0]["label"] == "AC-100%-unit"
        store.close()


# ---------------------------------------------------------------------------
# Service behaviour
# ---------------------------------------------------------------------------


class TestServiceFixes:
    @pytest.fixture
    def client(self, tmp_path):
        hub = Hub(create("synthetic", seed=5), store=Store(tmp_path / "s.db"), persist=False)
        # No live tasks needed; drive one packet in synchronously.
        hub.ingest(fx.advertisement_from(fx.default_population()[0], 0.0, __import__("random").Random(1)))
        hub.refresh()
        return TestClient(create_app(hub, allow_probe=False))

    def test_spa_route_blocks_path_traversal(self, client):
        r = client.get("/../../../../../../etc/passwd")
        assert r.status_code == 200  # the SPA shell, not the file
        assert "root:" not in r.text
        assert "<!doctype html>" in r.text.lower() or "<html" in r.text.lower()

    def test_feed_limit_zero_is_rejected(self, client):
        assert client.get("/api/feed?limit=0").status_code == 422

    def test_acknowledged_alert_survives_a_refresh(self, tmp_path):
        # Build a hub with a persistent separated tracker so an alert exists.
        hub = Hub(create("synthetic", seed=9), store=Store(tmp_path / "a.db"), persist=False)
        d = Device(key="72:0B:5D:E1:44:8C", address="72:0B:5D:E1:44:8C",
                   first_seen=time.time() - 1800)
        for _ in range(30):
            d.observe(parse(adv(fx.payload(fx.find_my(separated=True)),
                                address="72:0B:5D:E1:44:8C", random=True, rssi=-55)))
        d.identification = identify(d)
        hub.devices[d.key] = d
        hub._refresh_alerts()
        assert hub.alerts, "expected a separated-tracker alert"
        key = hub.alerts[0].key
        hub.acknowledge_alert(key)
        # A later sweep regenerates alerts; the dismissal must stick.
        hub._refresh_alerts()
        assert all(a.acknowledged for a in hub.alerts if a.key == key)


# ---------------------------------------------------------------------------
# Second review pass — defects found in the first round of fixes
# ---------------------------------------------------------------------------


class TestPurgeKeepsCaptureAlive:
    def test_purge_reopens_the_session_so_writes_still_work(self, tmp_path):
        # purge() deletes every sessions row, including the live one. With
        # foreign keys on, the next insert used to fail and take the ingest
        # loop down with it, silently ending capture for the process's life.
        store = Store(tmp_path / "p.db")
        hub = Hub(create("synthetic", seed=1), store=store, persist=True)
        hub.session_id = store.start_session("live", backend="synthetic", capabilities={})
        store.purge(keep_labels=True)
        hub.after_purge()
        assert hub.session_id is not None
        d = Device(key="AA:BB:CC:DD:EE:01", address="AA:BB:CC:DD:EE:01")
        store.snapshot_devices(hub.session_id, [d])  # must not raise IntegrityError

    def test_purge_clears_dismissals_it_just_deleted(self, tmp_path):
        store = Store(tmp_path / "p.db")
        hub = Hub(create("synthetic", seed=1), store=store, persist=False)
        hub._acknowledged = {"separated:AA": "attention"}
        store.purge(keep_labels=True)
        hub.after_purge()
        assert hub._acknowledged == {}


class TestRetentionScoping:
    def test_retention_never_deletes_the_live_session(self, tmp_path):
        store = Store(tmp_path / "r.db")
        session_id = store.start_session("live", backend="synthetic", capabilities={})
        store._conn.execute(
            "UPDATE sessions SET started_at=? WHERE id=?",
            (time.time() - 400 * 86400, session_id),
        )
        store._conn.commit()
        store.enforce_retention(exclude_session=session_id)
        assert [s["id"] for s in store.sessions()] == [session_id]

    def test_retention_still_ages_out_other_sessions(self, tmp_path):
        store = Store(tmp_path / "r.db")
        old = store.start_session("old", backend="synthetic", capabilities={})
        live = store.start_session("live", backend="synthetic", capabilities={})
        store._conn.execute(
            "UPDATE sessions SET started_at=? WHERE id=?", (time.time() - 400 * 86400, old)
        )
        store._conn.commit()
        store.enforce_retention(exclude_session=live)
        assert [s["id"] for s in store.sessions()] == [live]


class TestReplayPlan:
    def test_keyset_replay_does_not_sort(self, tmp_path):
        # Ordering by a column the chosen index does not cover makes SQLite sort
        # every remaining row of the session on each batch — slower than the
        # OFFSET scan the keyset pagination replaced.
        store = Store(tmp_path / "q.db")
        plan = " ".join(
            r[-1]
            for r in store._conn.execute(
                "EXPLAIN QUERY PLAN SELECT * FROM observations "
                "WHERE session_id=? AND id>? ORDER BY id ASC LIMIT ?",
                (1, 0, 10),
            )
        )
        assert "TEMP B-TREE" not in plan
        assert "idx_obs_session_id" in plan


class TestFollowAddressType:
    @pytest.mark.parametrize(
        "address", ["3C:9C:0F:44:21:AB", "00:1A:7D:DA:71:13", "B8:27:EB:12:34:56"]
    )
    def test_a_public_address_is_followed_as_public(self, address):
        # classify_address(addr, True) answers "given this is random, which
        # kind" — so feeding it a public MAC returns a confident random subtype
        # and the firmware's address+type filter then never matches.
        backend = create("nrf")
        backend._serial = _RecordingSerial()
        asyncio.run(backend.follow(address, address_type=AddressType.PUBLIC))
        assert backend._serial.follow_type_byte() == 0x00

    def test_an_unknown_type_defaults_to_public_not_random(self):
        backend = create("nrf")
        backend._serial = _RecordingSerial()
        asyncio.run(backend.follow("3C:9C:0F:44:21:AB", address_type=None))
        assert backend._serial.follow_type_byte() == 0x00

    @pytest.mark.parametrize(
        "kind",
        [AddressType.RANDOM_STATIC, AddressType.RESOLVABLE_PRIVATE,
         AddressType.NON_RESOLVABLE_PRIVATE],
    )
    def test_a_random_address_is_followed_as_random(self, kind):
        backend = create("nrf")
        backend._serial = _RecordingSerial()
        asyncio.run(backend.follow("72:0B:5D:E1:44:8C", address_type=kind))
        assert backend._serial.follow_type_byte() == 0x01

    def test_the_enum_value_string_is_accepted_too(self):
        # The HTTP layer used to flatten this to a string; both must work.
        backend = create("nrf")
        backend._serial = _RecordingSerial()
        asyncio.run(backend.follow("72:0B:5D:E1:44:8C", address_type="random_static"))
        assert backend._serial.follow_type_byte() == 0x01


class TestProbeResultSurvives:
    def _probed(self):
        from blemon.models import Category, Confidence, Evidence, Guess

        return Guess(label="Sony WF-1000XM5", confidence=Confidence.CERTAIN,
                     evidence=[Evidence("read from the device over GATT")],
                     category=Category.AUDIO, score=1.0)

    def test_absorb_carries_probe_guesses_onto_the_survivor(self):
        elder = Device(key="AA:BB:CC:DD:EE:01", address="AA:BB:CC:DD:EE:01")
        younger = Device(key="AA:BB:CC:DD:EE:02", address="AA:BB:CC:DD:EE:02")
        younger.probe_guesses = [self._probed()]
        elder.absorb(younger, 0.9, ["same payload"])
        assert [g.label for g in elder.probe_guesses] == ["Sony WF-1000XM5"]

    def test_probe_guesses_are_serialized_so_they_survive_a_restart(self):
        d = Device(key="AA:BB:CC:DD:EE:01", address="AA:BB:CC:DD:EE:01")
        d.probe_guesses = [self._probed()]
        assert d.to_dict()["probe_guesses"][0]["label"] == "Sony WF-1000XM5"

    def test_identify_does_not_grow_the_stored_evidence(self):
        # identify() stamps and merges into the guesses it is handed, so
        # returning the stored objects would grow this list on every tick — and
        # it is re-serialized into every snapshot and every SQLite row.
        d = Device(key="AA:BB:CC:DD:EE:01", address="AA:BB:CC:DD:EE:01")
        d.probe_guesses = [self._probed()]
        before = len(d.probe_guesses[0].evidence)
        for _ in range(5):
            d.identification = identify(d)
        assert len(d.probe_guesses[0].evidence) == before
        assert d.probe_guesses[0].matcher == ""


class TestAlertDismissalScoping:
    def _hub_with_alert(self, tmp_path):
        hub = Hub(create("synthetic", seed=9), store=Store(tmp_path / "a.db"), persist=False)
        d = Device(key="72:0B:5D:E1:44:8C", address="72:0B:5D:E1:44:8C",
                   first_seen=time.time() - 1800)
        for _ in range(30):
            d.observe(parse(adv(fx.payload(fx.find_my(separated=True)),
                                address="72:0B:5D:E1:44:8C", random=True, rssi=-55)))
        d.identification = identify(d)
        hub.devices[d.key] = d
        hub._refresh_alerts()
        return hub, d

    def test_an_escalated_alert_is_raised_again_after_dismissal(self, tmp_path):
        # A dismissal silences the level it was made at. Escalation — the same
        # tag turning up in a second place — is new information and is the
        # signal the whole feature exists to deliver.
        hub, device = self._hub_with_alert(tmp_path)
        assert hub.alerts
        hub._acknowledged = {a.key: "info" for a in hub.alerts}
        hub._refresh_alerts()
        assert any(not a.acknowledged for a in hub.alerts)

    def test_a_dismissal_at_the_same_level_still_sticks(self, tmp_path):
        hub, _ = self._hub_with_alert(tmp_path)
        key = hub.alerts[0].key
        hub.acknowledge_alert(key)
        hub._refresh_alerts()
        assert all(a.acknowledged for a in hub.alerts if a.key == key)

    def test_a_merge_carries_the_dismissal_to_the_surviving_key(self, tmp_path):
        # Alert keys embed the device key, and a merge keeps the elder's — so
        # without a remap the alert the user just dismissed comes straight back
        # under the survivor's key on the next sweep.
        hub = Hub(create("synthetic", seed=1), persist=False)
        hub._acknowledged = {"separated:BB:BB:BB:BB:BB:BB": "attention"}
        hub._address_index = {"BB:BB:BB:BB:BB:BB": "AA:AA:AA:AA:AA:AA"}
        hub._remap_acknowledged("BB:BB:BB:BB:BB:BB")
        assert hub._acknowledged.get("separated:AA:AA:AA:AA:AA:AA") == "attention"


class TestRedactionCoversEchoedAddresses:
    def test_a_mac_echoed_in_service_data_is_blanked(self):
        # pvvx/ATC sensors put their own MAC in the payload. Leaving it hands a
        # reader the real address next to its own pseudonym.
        mac = bytes.fromhex("A4C1381122FF")
        body = mac + bytes(9)
        raw = fx.payload(fx.service_data16(0x181A, body))
        out = redact_raw_payload(raw, "FF:22:11:38:C1:A4")
        assert mac not in out
        assert len(out) == len(raw)

    def test_the_le_device_address_ad_type_is_blanked(self):
        mac = bytes.fromhex("A4C1381122FF")
        raw = fx.payload(bytes([8, 0x1B]) + mac + bytes([0]))
        assert mac not in redact_raw_payload(raw, None)

    def test_redaction_fails_closed_on_a_malformed_structure(self):
        # The AD parser stops at a structure it cannot read. Redaction must not
        # ship the remainder verbatim just because it could not parse it.
        name = b"Sams iPhone"
        raw = bytes([0x40, 0xFF]) + bytes([len(name) + 1, 0x09]) + name
        assert b"Sams" not in redact_raw_payload(raw, None)

    def test_ordinary_padding_is_left_alone(self):
        raw = fx.payload(fx.complete_name("Speaker")) + bytes(6)
        out = redact_raw_payload(raw, None)
        assert len(out) == len(raw)
        assert b"Speaker" not in out


class TestBackendStatusIsHonest:
    def test_a_dead_ingest_loop_is_not_reported_as_running(self):
        # backend.describe() reports the backend's own status, which stays
        # "running" after _ingest has died — so the sweep's snapshot would
        # overwrite the error and the dashboard would show a healthy capture.
        from blemon.capture.base import BackendStatus

        hub = Hub(create("synthetic", seed=1), persist=False)
        hub.backend_status = BackendStatus("error", "Capture stopped: disk full")
        view = hub.backend_view()
        assert view["running"] is False
        assert view["status"]["state"] == "error"
        assert "disk full" in view["status"]["detail"]

    def test_a_healthy_backend_is_reported_as_the_backend_sees_it(self):
        hub = Hub(create("synthetic", seed=1), persist=False)
        assert hub.backend_view()["status"] == hub.backend.describe()["status"]


class TestCapabilityHonesty:
    def test_active_scan_fallback_admits_it_transmits(self):
        backend = create("bleak")
        assert backend.capabilities.can_transmit is False
        backend._scan_mode = "active"
        assert backend.capabilities.can_transmit is True

    def test_address_type_is_read_on_non_bluez_platforms(self):
        # Only BlueZ uses details={"props": ...}; matching just that shape
        # silently returns UNKNOWN for every device everywhere else, which
        # disables address-type privacy scoring instead of failing visibly.
        class WinRTDevice:
            class details:  # noqa: N801 — mirrors bleak's attribute shape
                address_type = "Public"

        assert (
            _resolve_address_type(WinRTDevice(), "3C:9C:0F:44:21:AB", False)
            is AddressType.PUBLIC
        )


class TestConcurrentReadsAreSafe:
    def test_serializing_devices_while_capturing_does_not_raise(self):
        # device_list() hands back live Device objects, and to_dict() iterates
        # deques and Counters the capture task mutates on every packet — so
        # serializing outside the lock raises "deque mutated during iteration"
        # and the sync endpoints 500 several times a minute in a busy room.
        import threading

        hub = Hub(create("synthetic", seed=4), persist=False)
        for i in range(40):
            address = f"AA:BB:CC:DD:EE:{i:02X}"
            hub.ingest(adv(fx.payload(fx.complete_name(f"Device {i}")), address=address))

        errors: list[BaseException] = []
        stop = threading.Event()

        def capture():
            i = 0
            while not stop.is_set():
                address = f"AA:BB:CC:DD:EE:{i % 40:02X}"
                try:
                    hub.ingest(adv(fx.payload(fx.complete_name("x")), address=address))
                except BaseException as exc:  # noqa: BLE001 — recorded, not swallowed
                    errors.append(exc)
                    return
                i += 1

        writer = threading.Thread(target=capture, daemon=True)
        writer.start()
        try:
            for _ in range(300):
                try:
                    hub.device_dicts()
                    hub.exposure_summary()
                except BaseException as exc:  # noqa: BLE001 — recorded, not swallowed
                    errors.append(exc)
                    break
        finally:
            stop.set()
            writer.join(timeout=5)
        assert not errors, f"concurrent read raised {errors[0]!r}"

    def test_the_purge_endpoint_leaves_capture_able_to_write(self, tmp_path):
        store = Store(tmp_path / "e.db")
        hub = Hub(create("synthetic", seed=2), store=store, persist=True)
        hub.session_id = store.start_session("live", backend="synthetic", capabilities={})
        client = TestClient(create_app(hub))

        response = client.post("/api/purge", json={"keep_labels": True})
        assert response.status_code == 200
        assert response.json()["session_id"] is not None

        for i in range(5):
            hub.ingest(adv(fx.payload(fx.complete_name("Speaker")),
                           address=f"AA:BB:CC:DD:EE:{i:02X}"))
        hub._flush()  # used to raise IntegrityError and kill the ingest task
        stored = store._conn.execute("SELECT COUNT(*) AS c FROM observations").fetchone()
        assert stored["c"] == 5
