"""Eddystone (service UUID 0xFEAA) and Google's Find My Device Network beacons.

Eddystone is the open beacon format: unlike iBeacon it can carry a URL and its
own telemetry in the clear, which makes it one of the most legible things on
the air.
"""

from __future__ import annotations

import struct
from typing import Any

from blemon.decode.registry import service_data_decoder
from blemon.models import Category, Decoding, Field_

EDDYSTONE_UUID = "FEAA"

URL_SCHEMES = {0x00: "http://www.", 0x01: "https://www.", 0x02: "http://", 0x03: "https://"}

URL_EXPANSIONS = {
    0x00: ".com/",
    0x01: ".org/",
    0x02: ".edu/",
    0x03: ".net/",
    0x04: ".info/",
    0x05: ".biz/",
    0x06: ".gov/",
    0x07: ".com",
    0x08: ".org",
    0x09: ".edu",
    0x0A: ".net",
    0x0B: ".info",
    0x0C: ".biz",
    0x0D: ".gov",
}

FRAME_NAMES = {
    0x00: "UID",
    0x10: "URL",
    0x20: "TLM",
    0x30: "EID",
    0x40: "Find My Device Network",
    0x41: "Find My Device Network (unwanted-tracking)",
}


def _expand_url(data: bytes) -> str:
    if not data:
        return ""
    out = [URL_SCHEMES.get(data[0], "")]
    for b in data[1:]:
        if b in URL_EXPANSIONS:
            out.append(URL_EXPANSIONS[b])
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


@service_data_decoder(EDDYSTONE_UUID, name="eddystone")
def decode_eddystone(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    if not data:
        return []
    frame = data[0]
    name = FRAME_NAMES.get(frame, f"unknown frame type 0x{frame:02X}")

    if frame == 0x00 and len(data) >= 18:
        power = struct.unpack("<b", data[1:2])[0]
        namespace = data[2:12].hex().upper()
        instance = data[12:18].hex().upper()
        return [
            Decoding(
                protocol="eddystone_uid",
                summary=f"Eddystone-UID {namespace}/{instance} @{power}dBm",
                fields=[
                    Field_("ranging_data", power, 1, 1, "calibrated RSSI at 0 metres"),
                    Field_("namespace", namespace, 2, 10, "identifies the operator"),
                    Field_("instance", instance, 12, 6, "identifies this specific beacon"),
                ],
                english=(
                    "An Eddystone-UID beacon: a fixed transmitter announcing a permanent "
                    f"identity ({namespace[:8]}…/{instance}). It never changes and never "
                    "listens. Whoever deployed it can tell exactly which beacon you walked "
                    "past and when, if you are running their app."
                ),
                category=Category.BEACON,
                tags=["eddystone", "static_identity", "plaintext_identity"],
            )
        ]

    if frame == 0x10 and len(data) >= 2:
        power = struct.unpack("<b", data[1:2])[0]
        url = _expand_url(data[2:])
        return [
            Decoding(
                protocol="eddystone_url",
                summary=f"Eddystone-URL {url} @{power}dBm",
                fields=[
                    Field_("ranging_data", power, 1, 1, "calibrated RSSI at 0 metres"),
                    Field_("url", url, 2, len(data) - 2, "compressed URL encoding"),
                ],
                english=(
                    f"This beacon is broadcasting a web address in the clear: {url}. "
                    "Anyone in range can read it without connecting to anything. It is the "
                    "closest thing BLE has to a physical hyperlink — typically a shop, a "
                    "museum exhibit, or a piece of signage."
                ),
                category=Category.BEACON,
                tags=["eddystone", "plaintext_content", "url"],
            )
        ]

    if frame == 0x20 and len(data) >= 14:
        version = data[1]
        if version == 0x00:
            vbatt, temp_raw, adv_cnt, sec_cnt = struct.unpack(">HhII", data[2:14])
            temp = temp_raw / 256.0
            uptime_s = sec_cnt / 10.0
            days = uptime_s / 86400.0
            return [
                Decoding(
                    protocol="eddystone_tlm",
                    summary=(
                        f"Eddystone-TLM {vbatt}mV {temp:.1f}°C "
                        f"{adv_cnt} adverts, up {days:.1f}d"
                    ),
                    fields=[
                        Field_("battery_mv", vbatt, 2, 2, "0 if not battery powered"),
                        Field_("temperature_c", round(temp, 2), 4, 2, "8.8 fixed point"),
                        Field_("advertising_count", adv_cnt, 6, 4, "since power-on"),
                        Field_("uptime_seconds", uptime_s, 10, 4, "0.1s resolution"),
                    ],
                    english=(
                        "This is a beacon reporting its own health, unencrypted: "
                        f"{vbatt} mV of battery, {temp:.1f} °C ambient, and it has been "
                        f"running for {days:.1f} days. The uptime counter is effectively a "
                        "serial number — it identifies this exact beacon even if everything "
                        "else about it changed."
                    ),
                    category=Category.BEACON,
                    tags=["eddystone", "telemetry", "plaintext_state", "counter_leak"],
                )
            ]
        return [
            Decoding(
                protocol="eddystone_etlm",
                summary=f"Eddystone-eTLM (encrypted telemetry, version 0x{version:02X})",
                fields=[Field_("encrypted_telemetry", data[2:].hex(), 2, len(data) - 2)],
                english=(
                    "A beacon reporting its health, but encrypted — only its operator can "
                    "read the battery and temperature. This is the privacy-respecting variant."
                ),
                category=Category.BEACON,
                tags=["eddystone", "encrypted"],
            )
        ]

    if frame == 0x30 and len(data) >= 10:
        power = struct.unpack("<b", data[1:2])[0]
        eid = data[2:10].hex().upper()
        return [
            Decoding(
                protocol="eddystone_eid",
                summary=f"Eddystone-EID {eid} @{power}dBm",
                fields=[
                    Field_("ranging_data", power, 1, 1),
                    Field_("ephemeral_id", eid, 2, 8, "rotates on a schedule known to the operator"),
                ],
                english=(
                    "An Eddystone-EID beacon. Unlike a plain UID beacon, the identifier here "
                    "rotates on a schedule, so only the operator's servers can tell which "
                    "beacon it is. To you it is an anonymous, changing token — this is the "
                    "privacy-preserving beacon design."
                ),
                category=Category.BEACON,
                tags=["eddystone", "rotating_identity"],
            )
        ]

    if frame in (0x40, 0x41):
        return [
            Decoding(
                protocol="google_find_my_device",
                summary=f"Google Find My Device Network beacon ({name})",
                fields=[
                    Field_("frame_type", f"0x{frame:02X}", 0, 1, name),
                    Field_("ephemeral_identifier", data[1:].hex().upper(), 1, len(data) - 1,
                           "rotating public key material"),
                ],
                english=(
                    "This is a Google Find My Device Network beacon — the Android counterpart "
                    "to Apple's Find My. A tag or phone is broadcasting a rotating key so that "
                    "passing Android devices can report its location to its owner. The "
                    "identifier rotates, so it is not directly trackable by you, but it does "
                    "mean a findable object is nearby."
                    + (
                        " This is the unwanted-tracking variant, which a tag emits when it has "
                        "been away from its owner — worth paying attention to."
                        if frame == 0x41
                        else ""
                    )
                ),
                category=Category.TRACKER,
                tags=["google", "find_my_device", "tracker", "rotating_identity"]
                + (["separated_tracker"] if frame == 0x41 else []),
            )
        ]

    return [
        Decoding(
            protocol="eddystone",
            summary=f"Eddystone {name}, {len(data)} bytes",
            fields=[
                Field_("frame_type", f"0x{frame:02X}", 0, 1, name),
                Field_("payload", data[1:].hex(), 1, len(data) - 1),
            ],
            english=(
                f"An Eddystone frame of type {name} that we do not decode in detail. "
                "The raw bytes are shown so you can inspect them yourself."
            ),
            category=Category.BEACON,
            tags=["eddystone", "undecoded_subtype"],
        )
    ]
