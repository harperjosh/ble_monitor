"""Microsoft manufacturer data (company 0x0006): Swift Pair and CDP beacons.

Windows machines and Xbox controllers announce themselves through two related
formats. The Connected Devices Platform beacon in particular leaks the device
*type* — desktop, laptop, phone, Xbox — in the clear.
"""

from __future__ import annotations

from typing import Any

from blemon.decode.registry import manufacturer_decoder
from blemon.models import Category, Decoding, Field_

MICROSOFT_COMPANY_ID = 0x0006

RE = "interpretation from Microsoft's published beacon format and community research"

CDP_DEVICE_TYPES: dict[int, str] = {
    1: "Xbox One",
    6: "iPhone",
    7: "iPad",
    8: "Android device",
    9: "Windows desktop",
    11: "Windows phone",
    12: "Linux device",
    13: "Windows IoT",
    14: "Surface Hub",
    15: "Windows laptop",
    16: "Windows tablet",
}

SWIFT_PAIR_SCENARIOS: dict[int, str] = {
    0x01: "pairing over LE only",
    0x02: "pairing over LE and BR/EDR",
    0x03: "BR/EDR with Secure Connections",
}

CATEGORY_FOR_TYPE = {
    1: Category.APPLIANCE,
    6: Category.PHONE,
    7: Category.COMPUTER,
    8: Category.PHONE,
    9: Category.COMPUTER,
    11: Category.PHONE,
    12: Category.COMPUTER,
    13: Category.APPLIANCE,
    14: Category.APPLIANCE,
    15: Category.COMPUTER,
    16: Category.COMPUTER,
}


@manufacturer_decoder(MICROSOFT_COMPANY_ID, name="microsoft")
def decode_microsoft(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    if not data:
        return []
    beacon_id = data[0]

    if beacon_id == 0x03:
        return _swift_pair(data)
    if beacon_id == 0x01:
        return _cdp_beacon(data)

    return [
        Decoding(
            protocol="microsoft",
            summary=f"Microsoft beacon, unrecognised scenario 0x{beacon_id:02X}",
            fields=[
                Field_("beacon_id", f"0x{beacon_id:02X}", 0, 1),
                Field_("payload", data[1:].hex(), 1, len(data) - 1),
            ],
            english="A Microsoft-format advertisement whose scenario byte we do not "
            "recognise. Raw bytes shown.",
            category=Category.COMPUTER,
            tags=["microsoft", "undecoded_subtype"],
        )
    ]


def _swift_pair(data: bytes) -> list[Decoding]:
    sub = data[1] if len(data) > 1 else 0
    sub_name = SWIFT_PAIR_SCENARIOS.get(sub, f"unknown sub-scenario 0x{sub:02X}")
    fields = [
        Field_("beacon_id", "0x03", 0, 1, "Swift Pair"),
        Field_("sub_scenario", f"0x{sub:02X}", 1, 1, sub_name),
    ]
    body = data[3:]  # byte 2 is a reserved RSSI byte
    addr = None
    if sub in (0x02, 0x03) and len(body) >= 6:
        addr = ":".join(f"{b:02X}" for b in body[:6][::-1])
        fields.append(Field_("bredr_address", addr, 3, 6, "classic Bluetooth address"))
        body = body[6:]
    display_name = body.decode("utf-8", errors="replace").strip("\x00") if body else ""
    if display_name:
        fields.append(Field_("display_name", display_name, None, len(body)))

    return [
        Decoding(
            protocol="microsoft_swift_pair",
            summary=f"Swift Pair: {display_name or '(no name)'} — {sub_name}",
            fields=fields,
            english=(
                "A Swift Pair accessory is in pairing mode — this is what makes Windows show "
                "an 'Add device?' toast. "
                + (
                    f"It is broadcasting its display name in plain text: “{display_name}”. "
                    if display_name
                    else ""
                )
                + (
                    f"It is also broadcasting its permanent classic-Bluetooth address ({addr}), "
                    "which does not rotate and so identifies this device indefinitely."
                    if addr
                    else "It only pairs over LE."
                )
            ),
            category=Category.PERIPHERAL,
            tags=["microsoft", "swift_pair", "pairing_mode", "plaintext_identity"]
            + (["static_identity"] if addr else []),
        )
    ]


def _cdp_beacon(data: bytes) -> list[Decoding]:
    if len(data) < 4:
        raise ValueError("short CDP beacon")
    version_devtype = data[1]
    version = version_devtype >> 5
    devtype = version_devtype & 0x1F
    devname = CDP_DEVICE_TYPES.get(devtype, f"unknown device type {devtype}")
    flags = data[2]
    salt = data[4:8].hex().upper() if len(data) >= 8 else None
    devhash = data[8:24].hex().upper() if len(data) >= 24 else None

    fields = [
        Field_("beacon_id", "0x01", 0, 1, "Connected Devices Platform"),
        Field_("version", version, 1, 1, RE),
        Field_("device_type", devtype, 1, 1, devname),
        Field_("flags", f"0x{flags:02X}", 2, 1, RE),
    ]
    if salt:
        fields.append(Field_("salt", salt, 4, 4, "rotates with the device hash"))
    if devhash:
        fields.append(
            Field_("device_hash", devhash, 8, 16, "SHA-256 over the salt and the account key")
        )

    return [
        Decoding(
            protocol="microsoft_cdp",
            summary=f"Microsoft CDP beacon: {devname}",
            fields=fields,
            english=(
                f"A Microsoft Connected Devices beacon — this is how Windows machines and "
                f"Xbox consoles find each other for Nearby Sharing and Phone Link. It says, "
                f"in the clear, that it is a {devname}. The identifier itself is salted and "
                "hashed, so it rotates, but the device type does not: you can tell what kind "
                "of machine it is without being able to tell which one."
            ),
            category=CATEGORY_FOR_TYPE.get(devtype, Category.COMPUTER),
            tags=["microsoft", "cdp", "device_type_leak", "rotating_identity"],
        )
    ]
