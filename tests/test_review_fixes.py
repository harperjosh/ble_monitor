"""Regression tests for defects found in code review.

Each test here corresponds to a specific bug fixed after the first review pass,
and fails against the code as it was before the fix.
"""

from __future__ import annotations

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
        # pvvx custom 0x181A: MAC(LE) + temp + hum + battery_mv + battery_pct.
        import struct

        mac = bytes.fromhex("A4C1381122FF")  # stored low-byte-first
        body = (
            mac
            + struct.pack("<h", 2134)  # 21.34 C
            + struct.pack("<H", 4850)  # 48.5 %
            + struct.pack("<H", 2977)  # battery mV
            + bytes([93])  # battery %
        )
        raw = fx.payload(fx.service_data16(0x181A, body))
        d = decoding(parse(adv(raw)), "environmental_sensing")
        battery = next(f.value for f in d.fields if f.name == "battery_percent")
        mv = next(f.value for f in d.fields if f.name == "battery_mv")
        addr = next(f.value for f in d.fields if f.name == "device_address")
        assert battery == 93
        assert mv == 2977
        assert addr == "FF:22:11:38:C1:A4"  # reversed for display


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
        import random

        hub = Hub(create("synthetic", seed=9), store=Store(tmp_path / "a.db"), persist=False)
        rng = random.Random(3)
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
        del rng
