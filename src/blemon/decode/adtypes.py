"""Advertising Data (AD) structure parsing.

An advertising payload is a sequence of ``[length][type][value...]`` elements.
This module turns those bytes into named, offset-tagged structures. It never
throws on malformed input — a truncated or nonsense payload is extremely common
in the wild and must produce a partial parse plus a recorded error, not a crash.
"""

from __future__ import annotations

import struct

from blemon.decode.assigned import (
    appearance_name,
    company_name,
    normalize_uuid,
    service_name,
)
from blemon.models import ADStructure, Field_

#: Core Specification Supplement, Part A — Data Types.
AD_TYPE_NAMES: dict[int, str] = {
    0x01: "Flags",
    0x02: "Incomplete List of 16-bit Service UUIDs",
    0x03: "Complete List of 16-bit Service UUIDs",
    0x04: "Incomplete List of 32-bit Service UUIDs",
    0x05: "Complete List of 32-bit Service UUIDs",
    0x06: "Incomplete List of 128-bit Service UUIDs",
    0x07: "Complete List of 128-bit Service UUIDs",
    0x08: "Shortened Local Name",
    0x09: "Complete Local Name",
    0x0A: "TX Power Level",
    0x0D: "Class of Device",
    0x0E: "Simple Pairing Hash C-192",
    0x0F: "Simple Pairing Randomizer R-192",
    0x10: "Device ID / Security Manager TK Value",
    0x11: "Security Manager Out of Band Flags",
    0x12: "Peripheral Connection Interval Range",
    0x14: "List of 16-bit Service Solicitation UUIDs",
    0x15: "List of 128-bit Service Solicitation UUIDs",
    0x16: "Service Data - 16-bit UUID",
    0x17: "Public Target Address",
    0x18: "Random Target Address",
    0x19: "Appearance",
    0x1A: "Advertising Interval",
    0x1B: "LE Bluetooth Device Address",
    0x1C: "LE Role",
    0x1D: "Simple Pairing Hash C-256",
    0x1E: "Simple Pairing Randomizer R-256",
    0x1F: "List of 32-bit Service Solicitation UUIDs",
    0x20: "Service Data - 32-bit UUID",
    0x21: "Service Data - 128-bit UUID",
    0x22: "LE Secure Connections Confirmation Value",
    0x23: "LE Secure Connections Random Value",
    0x24: "URI",
    0x25: "Indoor Positioning",
    0x26: "Transport Discovery Data",
    0x27: "LE Supported Features",
    0x28: "Channel Map Update Indication",
    0x29: "PB-ADV (Mesh provisioning)",
    0x2A: "Mesh Message",
    0x2B: "Mesh Beacon",
    0x2C: "BIGInfo",
    0x2D: "Broadcast Code",
    0x2E: "Resolvable Set Identifier",
    0x2F: "Advertising Interval - long",
    0x30: "Broadcast Name",
    0x31: "Encrypted Advertising Data",
    0x32: "Periodic Advertising Response Timing Information",
    0x3D: "Electronic Shelf Label",
    0x3F: "3D Information Data",
    0xFF: "Manufacturer Specific Data",
}

FLAG_BITS: list[tuple[int, str]] = [
    (0x01, "LE Limited Discoverable"),
    (0x02, "LE General Discoverable"),
    (0x04, "BR/EDR Not Supported"),
    (0x08, "Simultaneous LE and BR/EDR (Controller)"),
    (0x10, "Simultaneous LE and BR/EDR (Host)"),
]

LE_ROLES = {
    0x00: "Peripheral only",
    0x01: "Central only",
    0x02: "Peripheral preferred",
    0x03: "Central preferred",
}

URI_SCHEMES = {
    0x01: "",
    0x02: "aaa:",
    0x03: "aaas:",
    0x16: "http:",
    0x17: "https:",
    0x11: "ftp:",
    0x2A: "mailto:",
    0x39: "tel:",
    0x3F: "urn:",
}


def ad_type_name(code: int) -> str:
    return AD_TYPE_NAMES.get(code, f"Unknown AD type 0x{code:02X}")


def split_ad_structures(payload: bytes) -> tuple[list[tuple[int, int, bytes]], bytes, list[str]]:
    """Split a payload into ``(offset, type_code, value)`` triples.

    Returns the structures, any trailing bytes that were not part of a valid
    structure, and a list of human-readable parse errors. Trailing zero padding
    is normal (controllers pad to 31 bytes) and is not reported as an error.
    """
    out: list[tuple[int, int, bytes]] = []
    errors: list[str] = []
    i = 0
    n = len(payload)
    while i < n:
        length = payload[i]
        if length == 0:
            rest = payload[i:]
            if rest.strip(b"\x00"):
                errors.append(f"zero-length AD structure at offset {i} before non-zero data")
                return out, rest, errors
            return out, b"", errors  # ordinary padding
        if i + 1 + length > n:
            errors.append(
                f"AD structure at offset {i} claims {length} bytes but only "
                f"{n - i - 1} remain (truncated capture or malformed advertiser)"
            )
            return out, payload[i:], errors
        type_code = payload[i + 1]
        value = payload[i + 2 : i + 1 + length]
        out.append((i, type_code, value))
        i += 1 + length
    return out, b"", errors


def _uuids_from(data: bytes, width: int) -> list[str]:
    """Little-endian UUID list of the given byte width."""
    uuids = []
    for off in range(0, len(data) - width + 1, width):
        chunk = data[off : off + width][::-1]
        if width == 16:
            h = chunk.hex().upper()
            uuids.append(f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}")
        else:
            uuids.append(chunk.hex().upper())
    return uuids


def parse_structure(offset: int, type_code: int, data: bytes) -> ADStructure:
    """Structurally interpret one AD element (not ecosystem protocols)."""
    st = ADStructure(
        type_code=type_code,
        type_name=ad_type_name(type_code),
        data=data,
        offset=offset,
    )
    f = st.fields

    if type_code == 0x01 and data:
        bits = data[0]
        set_flags = [name for mask, name in FLAG_BITS if bits & mask]
        f.append(Field_("flags", set_flags, 0, 1, f"raw 0x{bits:02X}"))

    elif type_code in (0x02, 0x03, 0x14):
        for u in _uuids_from(data, 2):
            f.append(Field_("service_uuid", u, None, 2, service_name(u)))

    elif type_code in (0x04, 0x05, 0x1F):
        for u in _uuids_from(data, 4):
            f.append(Field_("service_uuid", u, None, 4, service_name(u)))

    elif type_code in (0x06, 0x07, 0x15):
        for u in _uuids_from(data, 16):
            f.append(Field_("service_uuid", u, None, 16, service_name(u)))

    elif type_code in (0x08, 0x09):
        name = data.decode("utf-8", errors="replace")
        f.append(
            Field_(
                "local_name",
                name,
                0,
                len(data),
                "shortened" if type_code == 0x08 else "complete",
            )
        )

    elif type_code == 0x0A and data:
        f.append(Field_("tx_power", struct.unpack("<b", data[:1])[0], 0, 1, "dBm at 1 metre"))

    elif type_code == 0x12 and len(data) >= 4:
        lo, hi = struct.unpack("<HH", data[:4])
        f.append(Field_("conn_interval_min_ms", lo * 1.25, 0, 2))
        f.append(Field_("conn_interval_max_ms", hi * 1.25, 2, 2))

    elif type_code == 0x16 and len(data) >= 2:
        uuid = data[1::-1].hex().upper()
        f.append(Field_("service_uuid", uuid, 0, 2, service_name(uuid)))
        f.append(Field_("service_data", data[2:].hex(), 2, len(data) - 2))

    elif type_code == 0x20 and len(data) >= 4:
        uuid = data[3::-1].hex().upper()
        f.append(Field_("service_uuid", uuid, 0, 4, service_name(uuid)))
        f.append(Field_("service_data", data[4:].hex(), 4, len(data) - 4))

    elif type_code == 0x21 and len(data) >= 16:
        uuid = _uuids_from(data[:16], 16)[0]
        f.append(Field_("service_uuid", uuid, 0, 16, service_name(uuid)))
        f.append(Field_("service_data", data[16:].hex(), 16, len(data) - 16))

    elif type_code == 0x19 and len(data) >= 2:
        value = struct.unpack("<H", data[:2])[0]
        f.append(Field_("appearance", value, 0, 2, appearance_name(value)))

    elif type_code == 0x1A and len(data) >= 2:
        interval = struct.unpack("<H", data[:2])[0]
        f.append(Field_("advertising_interval_ms", round(interval * 0.625, 2), 0, 2))

    elif type_code == 0x2F and len(data) >= 3:
        interval = int.from_bytes(data[:3], "little")
        f.append(Field_("advertising_interval_ms", round(interval * 0.625, 2), 0, 3))

    elif type_code == 0x1B and len(data) >= 7:
        addr = ":".join(f"{b:02X}" for b in data[5::-1])
        f.append(
            Field_(
                "device_address",
                addr,
                0,
                6,
                "random" if data[6] & 1 else "public",
            )
        )

    elif type_code == 0x1C and data:
        f.append(Field_("le_role", LE_ROLES.get(data[0], f"reserved 0x{data[0]:02X}"), 0, 1))

    elif type_code in (0x17, 0x18):
        for off in range(0, len(data) - 5, 6):
            addr = ":".join(f"{b:02X}" for b in data[off : off + 6][::-1])
            f.append(Field_("target_address", addr, off, 6))

    elif type_code == 0x24 and len(data) >= 1:
        scheme = URI_SCHEMES.get(data[0], f"<scheme 0x{data[0]:02X}>")
        f.append(Field_("uri", scheme + data[1:].decode("utf-8", errors="replace"), 0, len(data)))

    elif type_code == 0x30:
        f.append(Field_("broadcast_name", data.decode("utf-8", errors="replace"), 0, len(data)))

    elif type_code == 0x2E:
        f.append(Field_("resolvable_set_identifier", data.hex().upper(), 0, len(data)))

    elif type_code == 0xFF and len(data) >= 2:
        cid = struct.unpack("<H", data[:2])[0]
        f.append(Field_("company_id", cid, 0, 2, company_name(cid) or "unregistered"))
        f.append(Field_("manufacturer_data", data[2:].hex(), 2, len(data) - 2))

    if not f:
        f.append(Field_("raw", data.hex(), 0, len(data)))
    return st


def service_uuid_of(structure: ADStructure) -> str | None:
    """The service UUID a Service Data structure carries, normalised."""
    if structure.type_code not in (0x16, 0x20, 0x21):
        return None
    for fld in structure.fields:
        if fld.name == "service_uuid":
            return normalize_uuid(str(fld.value))
    return None


def service_data_body(structure: ADStructure) -> bytes:
    if structure.type_code == 0x16:
        return structure.data[2:]
    if structure.type_code == 0x20:
        return structure.data[4:]
    if structure.type_code == 0x21:
        return structure.data[16:]
    return b""
