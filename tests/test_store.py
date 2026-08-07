"""Storage, retention, purge and export tests."""

from __future__ import annotations

import csv
import io
import json
import struct
import time

import pytest

from blemon import fixtures as fx
from blemon.decode import parse
from blemon.device import Device
from blemon.identity import identify
from blemon.models import Advertisement, classify_address
from blemon.store import Store, devices_to_csv, devices_to_json, write_pcap
from blemon.store.export import (
    LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR,
    Redactor,
    ble_channel_to_rf,
    observations_to_csv,
)


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "test.db")
    yield s
    s.close()


def sample_advertisements(count: int = 30) -> list[Advertisement]:
    out = []
    base = time.time() - count
    for i in range(count):
        address = "AA:BB:CC:DD:EE:FF" if i % 2 else "5E:11:A3:7C:90:22"
        out.append(
            Advertisement(
                address=address,
                timestamp=base + i,
                rssi=-50 - (i % 30),
                address_type=classify_address(address, i % 2 == 0),
                raw=fx.payload(fx.flags(0x1A), fx.airpods(lid_count=i)),
                channel=37 + (i % 3),
                source="test",
            )
        )
    return out


class TestSessions:
    def test_session_lifecycle(self, store):
        sid = store.start_session("café", backend="synthetic", capabilities={"advertising": True})
        store.record_observations(sid, [(a.address, a) for a in sample_advertisements()])
        store.end_session(sid)

        sessions = store.sessions()
        assert len(sessions) == 1
        assert sessions[0]["name"] == "café"
        assert sessions[0]["observation_count"] == 30
        assert sessions[0]["capabilities"]["advertising"] is True
        assert sessions[0]["ended_at"] is not None

    def test_replay_round_trips_every_field(self, store):
        sid = store.start_session("s")
        originals = sample_advertisements(10)
        store.record_observations(sid, [(a.address, a) for a in originals])
        replayed = [adv for _key, adv in store.replay(sid)]
        assert len(replayed) == 10
        for a, b in zip(originals, replayed, strict=True):
            assert a.address == b.address
            assert a.raw == b.raw
            assert a.rssi == b.rssi
            assert a.channel == b.channel
            assert a.address_type is b.address_type

    def test_session_counts_across_sessions(self, store):
        key = "72:0B:5D:E1:44:8C"
        for name in ("home", "office", "train"):
            sid = store.start_session(name)
            device = Device(key=key, address=key)
            device.observe(parse(Advertisement(address=key, raw=fx.tile())))
            store.snapshot_devices(sid, [device])
            store.end_session(sid)
        assert store.session_counts_for_devices([key]) == {key: 3}


class TestLabels:
    def test_labels_round_trip(self, store):
        store.set_label("AA:BB", label="My AirPods", is_mine=True, notes="left drawer")
        got = store.get_label("AA:BB")
        assert got["label"] == "My AirPods"
        assert got["is_mine"] == 1
        assert got["notes"] == "left drawer"

    def test_partial_update_preserves_other_fields(self, store):
        store.set_label("AA:BB", label="Name", is_mine=True)
        store.set_label("AA:BB", notes="added later")
        got = store.get_label("AA:BB")
        assert got["label"] == "Name" and got["is_mine"] == 1 and got["notes"] == "added later"

    def test_labels_survive_a_purge(self, store):
        """Losing your own annotations because you cleared history would be obnoxious."""
        sid = store.start_session("s")
        store.record_observations(sid, [(a.address, a) for a in sample_advertisements(5)])
        store.set_label("AA:BB", label="Keep me", is_mine=True)
        store.purge(keep_labels=True)
        assert store.what_is_stored()["counts"]["observations"] == 0
        assert store.get_label("AA:BB")["label"] == "Keep me"

    def test_purge_can_take_labels_too_when_asked(self, store):
        store.set_label("AA:BB", label="Delete me")
        store.purge(keep_labels=False)
        assert store.get_label("AA:BB") is None


class TestRetention:
    def test_old_observations_age_out(self, store):
        sid = store.start_session("s")
        old = Advertisement(address="AA:BB", timestamp=time.time() - 40 * 86400, raw=b"\x02\x01\x06")
        new = Advertisement(address="AA:BB", timestamp=time.time(), raw=b"\x02\x01\x06")
        store.record_observations(sid, [("AA:BB", old), ("AA:BB", new)])
        store.retention.observation_days = 7
        removed = store.enforce_retention()
        assert removed.get("observations") == 1
        assert store.what_is_stored()["counts"]["observations"] == 1

    def test_hard_cap_trims_the_oldest_first(self, store):
        sid = store.start_session("s")
        store.record_observations(sid, [(a.address, a) for a in sample_advertisements(50)])
        store.retention.max_observations = 20
        store.enforce_retention()
        assert store.what_is_stored()["counts"]["observations"] == 20

    def test_what_is_stored_is_specific(self, store):
        sid = store.start_session("s")
        store.record_observations(sid, [(a.address, a) for a in sample_advertisements(12)])
        info = store.what_is_stored()
        assert info["counts"]["observations"] == 12
        assert info["distinct_addresses"] == 2
        assert "not uploaded" in info["note"] or "uploaded anywhere" in info["note"]
        assert info["retention"]["observation_days"] > 0  # bounded by default


class TestPcapExport:
    def test_header_declares_the_right_link_type(self, tmp_path):
        path = tmp_path / "c.pcap"
        write_pcap(str(path), sample_advertisements(5))
        raw = path.read_bytes()
        magic, major, minor, _tz, _sf, snaplen, network = struct.unpack("<IHHiIII", raw[:24])
        assert magic == 0xA1B2C3D4
        assert (major, minor) == (2, 4)
        assert snaplen == 65535
        assert network == LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR

    def test_records_carry_the_advertising_access_address(self, tmp_path):
        path = tmp_path / "c.pcap"
        write_pcap(str(path), sample_advertisements(3))
        raw = path.read_bytes()[24:]
        _ts, _us, incl, orig = struct.unpack("<IIII", raw[:16])
        assert incl == orig
        body = raw[16 : 16 + incl]
        access_address = struct.unpack("<I", body[10:14])[0]
        assert access_address == 0x8E89BED6

    def test_channel_mapping_matches_the_rf_band_layout(self):
        assert ble_channel_to_rf(37) == 0     # below every data channel
        assert ble_channel_to_rf(38) == 12    # in the middle
        assert ble_channel_to_rf(39) == 39    # at the top
        assert ble_channel_to_rf(0) == 1
        assert ble_channel_to_rf(11) == 13
        assert ble_channel_to_rf(None) == 0

    @pytest.mark.parametrize("redact", [False, True])
    def test_an_independent_dissector_can_parse_it(self, tmp_path, redact):
        """Wireshark compatibility is the whole point, so verify with a real
        BLE dissector rather than trusting our own byte layout."""
        scapy = pytest.importorskip("scapy.layers.bluetooth4LE")
        from scapy.all import rdpcap

        path = tmp_path / "c.pcap"
        write_pcap(str(path), sample_advertisements(20), redact=redact)
        packets = rdpcap(str(path))
        assert len(packets) == 20
        parsed = [p for p in packets if p.haslayer(scapy.BTLE_ADV)]
        assert len(parsed) == 20


class TestRedaction:
    def test_redaction_is_stable_within_a_file_and_hides_the_real_address(self):
        r = Redactor(enabled=True)
        a = r.address("AA:BB:CC:DD:EE:FF")
        assert a == r.address("AA:BB:CC:DD:EE:FF")
        assert a != r.address("AA:BB:CC:DD:EE:00")
        assert "AA:BB:CC" not in a

    def test_two_exports_do_not_correlate(self):
        one = Redactor(enabled=True).address("AA:BB:CC:DD:EE:FF")
        two = Redactor(enabled=True).address("AA:BB:CC:DD:EE:FF")
        assert one != two

    def test_disabled_redaction_is_a_passthrough(self):
        assert Redactor(enabled=False).address("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"

    def test_json_export_redacts_names_too(self):
        """A device name is very often a person's own name."""
        device = Device(key="AA:BB", address="AA:BB")
        device.observe(parse(Advertisement(
            address="AA:BB", raw=fx.payload(fx.complete_name("Sam's iPhone")))))
        doc = json.loads(devices_to_json([{"snapshot": device.to_dict()}], redact=True))
        blob = json.dumps(doc)
        assert "Sam" not in blob
        assert "AA:BB" not in blob
        assert doc["redacted"] is True


class TestTabularExport:
    def _rows(self):
        device = Device(key="AA:BB:CC:DD:EE:FF", address="AA:BB:CC:DD:EE:FF")
        for _ in range(4):
            device.observe(parse(Advertisement(
                address="AA:BB:CC:DD:EE:FF", rssi=-55,
                raw=fx.payload(fx.flags(0x1A), fx.airpods()))))
        device.identification = identify(device)
        return [{"snapshot": device.to_dict()}]

    def test_csv_has_a_header_and_one_row_per_device(self):
        text = devices_to_csv(self._rows())
        rows = list(csv.DictReader(io.StringIO(text)))
        assert len(rows) == 1
        assert rows[0]["category"] == "audio"
        assert rows[0]["exposure_band"]
        assert rows[0]["confidence"]

    def test_observation_csv(self):
        rows = [{
            "ts": 1.0, "device_key": "AA:BB", "address": "AA:BB", "rssi": -50,
            "channel": 37, "pdu_type": "ADV_IND", "phy": "1M", "scan_rsp": 0,
            "source": "test", "raw": b"\x02\x01\x06",
        }]
        parsed = list(csv.DictReader(io.StringIO(observations_to_csv(rows))))
        assert parsed[0]["raw_hex"] == "020106"
        assert parsed[0]["channel"] == "37"
