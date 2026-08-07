"""Decoder tests.

The whole decode layer is verifiable with no radio hardware present, which is
the point: CI must be able to prove the decoders still work without anyone
plugging in a dongle. Payloads are built by ``blemon.fixtures`` with real
framing — length bytes computed the way a controller computes them — so these
exercise the AD parser as well as the protocol decoders.
"""

from __future__ import annotations

import pytest

from blemon import fixtures as fx
from blemon.decode import parse
from blemon.decode.adtypes import split_ad_structures
from blemon.decode.assigned import appearance_name, company_name, service_name
from blemon.models import AddressType, Advertisement, Category, classify_address


def adv(raw: bytes, address: str = "AA:BB:CC:DD:EE:FF", random: bool = False, rssi: int = -55):
    return Advertisement(
        address=address,
        raw=raw,
        rssi=rssi,
        address_type=classify_address(address, random),
    )


def decode(raw: bytes, **kw):
    parsed = parse(adv(raw, **kw))
    assert not parsed.parse_errors, parsed.parse_errors
    assert parsed.trailing == b"", parsed.trailing.hex()
    return parsed


def protocols(parsed) -> set[str]:
    return {d.protocol for d in parsed.decodings}


def find(parsed, protocol: str):
    for d in parsed.decodings:
        if d.protocol == protocol:
            return d
    raise AssertionError(f"{protocol} not decoded; got {sorted(protocols(parsed))}")


def field(decoding, name):
    for f in decoding.fields:
        if f.name == name:
            return f
    raise AssertionError(f"field {name!r} not in {[f.name for f in decoding.fields]}")


# ---------------------------------------------------------------------------
# AD structure parsing
# ---------------------------------------------------------------------------


class TestADParsing:
    def test_splits_well_formed_payload(self):
        payload = fx.payload(fx.flags(), fx.complete_name("Test"), fx.tx_power(-4))
        structures, trailing, errors = split_ad_structures(payload)
        assert [t for _, t, _ in structures] == [0x01, 0x09, 0x0A]
        assert trailing == b"" and errors == []

    def test_zero_padding_is_not_an_error(self):
        """Controllers pad advertisements to 31 bytes. That is normal, not damage."""
        payload = fx.payload(fx.flags(), fx.complete_name("Pad")) + bytes(12)
        structures, trailing, errors = split_ad_structures(payload)
        assert len(structures) == 2
        assert trailing == b"" and errors == []

    def test_truncated_structure_yields_partial_parse_not_an_exception(self):
        payload = fx.payload(fx.flags()) + bytes([0x14, 0x09]) + b"cut"
        structures, trailing, errors = split_ad_structures(payload)
        assert len(structures) == 1  # the flags survived
        assert trailing and errors and "truncated" in errors[0]

    def test_garbage_never_raises(self):
        for raw in (b"", b"\xff", b"\x00\x00\x00", bytes(range(64)), b"\xff" * 40):
            parse(adv(raw))  # must not raise

    @pytest.mark.parametrize(
        "builder,expected",
        [
            (lambda: fx.complete_name("Kitchen Scale"), "Kitchen Scale"),
            (lambda: fx.short_name("Kitch"), "Kitch"),
        ],
    )
    def test_names(self, builder, expected):
        assert decode(fx.payload(builder())).local_name == expected

    def test_flags_and_appearance_and_tx_power(self):
        parsed = decode(fx.payload(fx.flags(0x06), fx.appearance(0x03C1), fx.tx_power(-8)))
        assert "BR/EDR Not Supported" in parsed.flags
        assert parsed.appearance_name == "Human Interface Device / Keyboard"
        assert parsed.tx_power == -8

    def test_service_uuids_of_all_widths(self):
        parsed = decode(
            fx.payload(
                fx.service_uuids16(0x180D, 0x180F),
                fx.service_uuid128("6E400001-B5A3-F393-E0A9-E50E24DCCA9E"),
            )
        )
        assert "180D" in parsed.service_uuids
        assert "180F" in parsed.service_uuids
        assert "6E400001-B5A3-F393-E0A9-E50E24DCCA9E" in parsed.service_uuids


# ---------------------------------------------------------------------------
# Apple
# ---------------------------------------------------------------------------


class TestApple:
    def test_nearby_info_reports_activity_and_flags_plaintext_state(self):
        d = find(decode(fx.payload(fx.flags(0x1A), fx.apple_nearby_info(action=0x07))),
                 "apple_nearby_info")
        assert "Active user" in d.summary
        assert "plaintext_state" in d.tags
        assert d.english and "nothing here is encrypted" in d.english.lower()

    def test_interpreted_bits_carry_their_provenance(self):
        """Field semantics come from reverse-engineering, and must say so."""
        d = find(decode(fx.payload(fx.apple_nearby_info())), "apple_nearby_info")
        assert "reverse-engineering" in (field(d, "action_code").note or "")

    def test_ibeacon_uuid_major_minor(self):
        d = find(decode(fx.payload(fx.ibeacon(major=41, minor=7, power=-62))), "ibeacon")
        assert field(d, "proximity_uuid").value == "B9407F30-F5F8-466E-AFF9-25556B57FE6D"
        assert field(d, "major").value == 41
        assert field(d, "minor").value == 7
        assert field(d, "measured_power").value == -62
        assert d.category is Category.BEACON

    def test_airpods_battery_and_lid_counter(self):
        d = find(decode(fx.payload(fx.airpods(model=0x1420, left=8, right=7, case=5,
                                              lid_count=42))),
                 "apple_proximity_pairing")
        assert field(d, "model").note == "AirPods Pro (2nd generation)"
        assert field(d, "battery_left").value == "80%"
        assert field(d, "battery_right").value == "70%"
        assert field(d, "battery_case").value == "50%"
        assert field(d, "lid_open_counter").value == 42
        assert "counter_leak" in d.tags

    def test_airpods_unknown_battery_nibble(self):
        d = find(decode(fx.payload(fx.airpods(left=15, right=15, case=15))),
                 "apple_proximity_pairing")
        assert field(d, "battery_left").value == "unknown"

    def test_find_my_separated_carries_a_rotating_key(self):
        d = find(decode(fx.payload(fx.find_my(separated=True, battery=2))), "apple_find_my")
        assert "separated" in d.summary
        assert field(d, "battery_level").value == "low"
        assert len(field(d, "public_key").value) == 44  # 22 bytes as hex
        assert {"tracker", "rotating_identity"} <= set(d.tags)

    def test_find_my_nearby_form_has_no_key(self):
        d = find(decode(fx.payload(fx.find_my(separated=False))), "apple_find_my")
        assert "nearby" in d.summary
        assert not any(f.name == "public_key" for f in d.fields)

    def test_handoff_sequence_number(self):
        d = find(decode(fx.payload(fx.apple_handoff(seq=4207))), "apple_handoff")
        assert field(d, "sequence_number").value == 4207

    def test_airdrop_contact_hashes(self):
        d = find(decode(fx.payload(fx.apple_airdrop())), "apple_airdrop")
        assert "contact_hash_leak" in d.tags

    def test_hotspot_leaks_battery(self):
        d = find(decode(fx.payload(fx.apple_hotspot(battery=74, bars=3))),
                 "apple_tethering_source")
        assert field(d, "battery_percent").value == 74
        assert "battery_leak" in d.tags

    def test_homekit_static_identifier(self):
        d = find(decode(fx.payload(fx.apple_homekit(dev_id="AA:BB:CC:DD:EE:01"))), "apple_homekit")
        assert field(d, "device_id").value == "AA:BB:CC:DD:EE:01"
        assert "static_identity" in d.tags

    def test_nearby_action(self):
        d = find(decode(fx.payload(fx.apple_nearby_action(0x09))), "apple_nearby_action")
        assert "iOS setup" in d.summary

    def test_multiple_continuity_messages_in_one_payload(self):
        parsed = decode(fx.payload(fx.flags(0x1A), fx.apple_handoff(), fx.apple_airdrop()))
        assert {"apple_handoff", "apple_airdrop"} <= protocols(parsed)

    def test_unknown_subtype_is_reported_not_swallowed(self):
        raw = fx.payload(fx.manufacturer(0x004C, fx.continuity(0x7F, b"\x01\x02\x03")))
        d = find(decode(raw), "apple_continuity")
        assert "undecoded_subtype" in d.tags
        assert "0x7F" in field(d, "continuity_type").value


# ---------------------------------------------------------------------------
# Eddystone and Google
# ---------------------------------------------------------------------------


class TestEddystone:
    def test_url_expansion(self):
        d = find(decode(fx.eddystone_url("example", scheme=0x03, suffix=0x07)), "eddystone_url")
        assert field(d, "url").value == "https://example.com"

    def test_uid_namespace_and_instance(self):
        d = find(decode(fx.eddystone_uid()), "eddystone_uid")
        assert field(d, "namespace").value == "0102030405060708090A"
        assert field(d, "instance").value == "000000000001"

    def test_tlm_telemetry(self):
        d = find(decode(fx.eddystone_tlm(mv=2979, temp_c=21.5, adv_count=250413)), "eddystone_tlm")
        assert field(d, "battery_mv").value == 2979
        assert field(d, "temperature_c").value == pytest.approx(21.5, abs=0.01)
        assert field(d, "advertising_count").value == 250413

    def test_eid_is_marked_as_rotating(self):
        body = bytes([0x30, 0xEC]) + b"\x01" * 8
        raw = fx.payload(fx.service_uuids16(0xFEAA), fx.service_data16(0xFEAA, body))
        assert "rotating_identity" in find(decode(raw), "eddystone_eid").tags

    def test_find_my_device_network_unwanted_tracking_frame(self):
        d = find(decode(fx.google_find_my_device(unwanted=True)), "google_find_my_device")
        assert "separated_tracker" in d.tags
        assert d.category is Category.TRACKER


class TestFastPair:
    def test_discoverable_model_id(self):
        d = find(decode(fx.fast_pair_discoverable(0x0001F0)), "fast_pair")
        assert "Google Pixel Buds" in d.summary
        assert "pairing_mode" in d.tags

    def test_unknown_model_is_not_invented(self):
        d = find(decode(fx.fast_pair_discoverable(0xABCDEF)), "fast_pair")
        assert "0xABCDEF" in d.summary
        assert "not in our local model table" in (field(d, "model_id").note or "")

    def test_paired_mode_is_rotating_and_reports_battery(self):
        d = find(decode(fx.fast_pair_paired(battery=(72, 68, 90))), "fast_pair")
        assert "rotating_identity" in d.tags
        assert field(d, "battery_levels").value == ["72%", "68%", "90%"]


class TestMicrosoft:
    def test_cdp_device_type_is_in_the_clear(self):
        d = find(decode(fx.payload(fx.flags(), fx.microsoft_cdp(15))), "microsoft_cdp")
        assert "Windows laptop" in d.summary
        assert "device_type_leak" in d.tags

    def test_swift_pair_display_name(self):
        d = find(decode(fx.payload(fx.flags(), fx.microsoft_swift_pair("Surface Mouse"))),
                 "microsoft_swift_pair")
        assert field(d, "display_name").value == "Surface Mouse"
        assert "plaintext_identity" in d.tags


# ---------------------------------------------------------------------------
# Sensors
# ---------------------------------------------------------------------------


class TestSensors:
    def test_bthome_values_round_trip(self):
        d = find(decode(fx.bthome(temperature=21.34, humidity=48.5, battery=93)), "bthome")
        assert field(d, "temperature").value == pytest.approx(21.34)
        assert field(d, "humidity").value == pytest.approx(48.5)
        assert field(d, "battery").value == 93

    def test_bthome_motion_is_flagged_as_an_occupancy_leak(self):
        d = find(decode(fx.bthome(motion=True)), "bthome")
        assert field(d, "motion").value == "detected"
        assert "occupancy_leak" in d.tags

    def test_bthome_encrypted_payload_is_not_guessed_at(self):
        raw = fx.payload(fx.flags(), fx.service_data16(0xFCD2, bytes([0x41]) + b"\xde\xad\xbe\xef"))
        d = find(decode(raw), "bthome")
        assert "encrypted" in d.tags
        assert not any(f.name == "temperature" for f in d.fields)

    def test_xiaomi_temperature_humidity_and_mac_in_payload(self):
        d = find(decode(fx.xiaomi_thermometer(22.4, 51.2)), "xiaomi_mibeacon")
        value = field(d, "temperature_and_humidity").value
        assert value["temperature_c"] == pytest.approx(22.4)
        assert value["humidity_percent"] == pytest.approx(51.2)
        assert "mac_in_payload" in d.tags

    def test_ruuvi_full_frame(self):
        d = find(decode(fx.payload(fx.flags(), fx.ruuvi(19.36, 43.5, 1013.2, moves=66))), "ruuvi")
        assert field(d, "temperature_c").value == pytest.approx(19.36, abs=0.01)
        assert field(d, "humidity_percent").value == pytest.approx(43.5, abs=0.01)
        assert field(d, "pressure_hpa").value == pytest.approx(1013.2, abs=0.01)
        assert field(d, "movement_counter").value == 66

    def test_govee(self):
        d = find(decode(fx.payload(fx.flags(), fx.govee(23.4, 46.0, 88))), "govee")
        assert field(d, "temperature_c").value == pytest.approx(23.4, abs=0.05)
        assert field(d, "battery_percent").value == 88

    def test_heart_rate_is_marked_sensitive(self):
        d = find(decode(fx.heart_rate(bpm=71)), "gatt_heart_rate")
        assert field(d, "heart_rate_bpm").value == 71
        assert {"health_data", "sensitive"} <= set(d.tags)

    def test_battery_service(self):
        d = find(decode(fx.battery_only(61)), "gatt_battery")
        assert field(d, "battery_percent").value == 61

    def test_exposure_notification_is_marked_privacy_preserving(self):
        d = find(decode(fx.exposure_notification()), "exposure_notification")
        assert "privacy_preserving" in d.tags


class TestTrackers:
    def test_tile(self):
        d = find(decode(fx.tile()), "tile")
        assert "tracker" in d.tags

    def test_samsung_smarttag(self):
        d = find(decode(fx.samsung_smarttag()), "samsung_smarttag")
        assert {"tracker", "rotating_identity"} <= set(d.tags)


# ---------------------------------------------------------------------------
# Unknown payloads
# ---------------------------------------------------------------------------


class TestUnknown:
    def test_unregistered_company_is_named_honestly(self):
        d = find(decode(fx.payload(fx.flags(), fx.manufacturer(0xF00D, b"\x01\x02\x03"))),
                 "manufacturer_data")
        assert "undecoded" in d.tags
        assert "0xF00D" in field(d, "company_id").value

    def test_unknown_service_data_still_shows_its_bytes(self):
        raw = fx.payload(fx.service_data16(0x1234, b"\xaa\xbb\xcc"))
        d = find(decode(raw), "service_data")
        assert field(d, "payload").value == "aabbcc"

    def test_a_broken_decoder_cannot_kill_a_capture(self):
        from blemon.decode.registry import _MANUFACTURER, decode_manufacturer

        def boom(_data, _context):
            raise ValueError("deliberate")

        _MANUFACTURER.setdefault(0x9999, []).append(("boom", boom))
        try:
            results = decode_manufacturer(0x9999, b"\x01", {})
            assert results and "decoder_error" in results[0].tags
        finally:
            _MANUFACTURER.pop(0x9999, None)


# ---------------------------------------------------------------------------
# Assigned numbers
# ---------------------------------------------------------------------------


class TestAssignedNumbers:
    def test_company_ids(self):
        assert company_name(0x004C) == "Apple, Inc."
        assert company_name(0x0006) == "Microsoft"
        assert company_name(0xFFFE) is None

    def test_service_names_prefer_what_the_uuid_is_used_for(self):
        assert "Eddystone" in service_name("FEAA")
        assert "Fast Pair" in service_name("FE2C")
        assert service_name("180D") == "Heart Rate"

    def test_long_form_uuids_collapse_to_the_short_registry(self):
        assert service_name("0000180D-0000-1000-8000-00805F9B34FB") == "Heart Rate"

    def test_appearance(self):
        assert appearance_name(0x0941) == "Wearable Audio Device / Earbud"
        assert appearance_name(0x0040) == "Phone"
        assert appearance_name(0x00C0) == "Watch"


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "address,random,expected",
    [
        ("AC:DE:48:00:11:22", False, AddressType.PUBLIC),
        ("C1:23:45:67:89:AB", True, AddressType.RANDOM_STATIC),
        ("5E:11:A3:7C:90:22", True, AddressType.RESOLVABLE_PRIVATE),
        ("2E:11:A3:7C:90:22", True, AddressType.NON_RESOLVABLE_PRIVATE),
        ("9E:11:A3:7C:90:22", True, AddressType.UNKNOWN),  # 0b10 is reserved
    ],
)
def test_address_classification(address, random, expected):
    assert classify_address(address, random) is expected


def test_rotating_and_stable_are_mutually_exclusive():
    for kind in AddressType:
        assert not (kind.is_rotating and kind.is_stable)
