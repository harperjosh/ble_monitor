"""Export: JSON, CSV and PCAP.

PCAP output uses ``LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`` (256) so captures open
directly in Wireshark with its full BLE dissector, which is a far better packet
inspector than anything worth reimplementing here.

Every export offers MAC redaction. Redaction is a keyed hash with a salt
generated per export, so addresses stay consistent *within* one file — the data
remains analysable — but cannot be correlated back to real hardware or across
two separate exports.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import struct
import time
from collections.abc import Iterable
from typing import Any

from blemon.models import Advertisement

#: libpcap link type for BLE link-layer packets with the pseudo-header.
LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256

#: The fixed access address used on the three primary advertising channels.
BLE_ADVERTISING_ACCESS_ADDRESS = 0x8E89BED6

# Pseudo-header flag bits.
PHDR_DEWHITENED = 0x0001
PHDR_SIGNAL_VALID = 0x0002
PHDR_NOISE_VALID = 0x0004
PHDR_DECRYPTED = 0x0008
PHDR_REF_AA_VALID = 0x0010
PHDR_AA_OFFENSES_VALID = 0x0020
PHDR_CHANNEL_ALIASED = 0x0040
PHDR_CRC_CHECKED = 0x0400
PHDR_CRC_VALID = 0x0800


#: AD types whose value is a device's advertised local name — frequently a
#: person's own name ("Sam's iPhone"). Blanked from raw payloads on redaction.
_NAME_AD_TYPES = (0x08, 0x09)


def redact_raw_payload(raw: bytes) -> bytes:
    """Return the raw AD payload with any Local Name value blanked.

    Redacting the address and name fields of a row while emitting the raw hex
    verbatim would leak the name straight back out — the name is right there in
    the bytes. This walks the AD structures and zeroes the name values, leaving
    the rest of the payload (and its framing) intact for analysis.
    """
    if not raw:
        return raw
    out = bytearray(raw)
    i = 0
    n = len(out)
    while i < n:
        length = out[i]
        if length == 0 or i + 1 + length > n:
            break
        type_code = out[i + 1]
        if type_code in _NAME_AD_TYPES:
            for j in range(i + 2, i + 1 + length):
                out[j] = 0
        i += 1 + length
    return bytes(out)


class Redactor:
    """Stable-within-a-file pseudonyms for addresses."""

    def __init__(self, enabled: bool = False, salt: bytes | None = None):
        self.enabled = enabled
        self.salt = salt if salt is not None else os.urandom(16)

    def address(self, addr: str) -> str:
        if not self.enabled:
            return addr
        digest = hashlib.blake2b(
            addr.upper().encode("utf-8"), key=self.salt, digest_size=3
        ).hexdigest()
        return f"XX:XX:XX:{digest[0:2]}:{digest[2:4]}:{digest[4:6]}".upper()

    def address_bytes(self, addr: str) -> bytes:
        """Six bytes, little-endian as they appear on the wire."""
        text = self.address(addr)
        parts = text.split(":")
        out = []
        for p in parts:
            try:
                out.append(int(p, 16))
            except ValueError:
                out.append(0)
        return bytes(reversed(out[:6])).ljust(6, b"\x00")

    def describe(self) -> str:
        return (
            "Addresses in this export are keyed hashes, consistent within this file only."
            if self.enabled
            else "Addresses in this export are the real observed addresses."
        )


def ble_channel_to_rf(channel: int | None) -> int:
    """BLE channel index to RF channel index, as the PCAP header expects.

    Advertising channels are not contiguous in the RF band: 37 sits below all
    the data channels, 38 sits in the middle and 39 sits at the top.
    """
    if channel is None:
        return 0
    if channel == 37:
        return 0
    if channel == 38:
        return 12
    if channel == 39:
        return 39
    if 0 <= channel <= 10:
        return channel + 1
    if 11 <= channel <= 36:
        return channel + 2
    return 0


# ---------------------------------------------------------------------------
# PCAP
# ---------------------------------------------------------------------------


def pcap_global_header() -> bytes:
    return struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # magic, microsecond resolution
        2,
        4,
        0,  # thiszone
        0,  # sigfigs
        65535,  # snaplen
        LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR,
    )


def _adv_pdu_header(adv: Advertisement, payload_len: int) -> bytes:
    """Reconstruct the two-byte advertising PDU header.

    We are rebuilding this from a decoded advertisement rather than replaying
    captured link-layer bytes, because a host adapter never gives us the real
    header. The PDU type and the TxAdd bit are recoverable and correct; the
    rest is zero. Sniffer-sourced packets carry their true header instead.
    """
    pdu_types = {
        "ADV_IND": 0x0,
        "ADV_DIRECT_IND": 0x1,
        "ADV_NONCONN_IND": 0x2,
        "SCAN_REQ": 0x3,
        "SCAN_RSP": 0x4,
        "CONNECT_IND": 0x5,
        "ADV_SCAN_IND": 0x6,
        "ADV_EXT_IND": 0x7,
        "AUX_ADV_IND": 0x7,
    }
    pdu_type = pdu_types.get(adv.pdu_type.value, 0x0)
    if adv.scan_response:
        pdu_type = 0x4
    tx_add = 0x40 if adv.address_type.value not in ("public", "opaque") else 0x00
    return bytes([pdu_type | tx_add, payload_len & 0xFF])


def pcap_record(adv: Advertisement, redactor: Redactor | None = None) -> bytes:
    """One PCAP record: pseudo-header + access address + PDU + CRC placeholder."""
    redactor = redactor or Redactor(enabled=False)

    addr_bytes = redactor.address_bytes(adv.address)
    raw = redact_raw_payload(adv.raw) if redactor.enabled else adv.raw
    ll_payload = addr_bytes + raw
    pdu = _adv_pdu_header(adv, len(ll_payload)) + ll_payload

    flags = PHDR_DEWHITENED | PHDR_REF_AA_VALID
    if adv.rssi is not None:
        flags |= PHDR_SIGNAL_VALID
    if adv.channel is None:
        # We do not know which channel it arrived on, and the header has no way
        # to say "unknown", so mark it aliased rather than assert channel 37.
        flags |= PHDR_CHANNEL_ALIASED

    phdr = struct.pack(
        "<BbbBIH",
        ble_channel_to_rf(adv.channel),
        adv.rssi if adv.rssi is not None else 0,
        0,  # noise power, not measured
        0,  # access address offenses
        BLE_ADVERTISING_ACCESS_ADDRESS,
        flags,
    )

    body = (
        phdr
        + struct.pack("<I", BLE_ADVERTISING_ACCESS_ADDRESS)
        + pdu
        + b"\x00\x00\x00"  # CRC not recoverable from a host adapter
    )
    ts = adv.timestamp
    header = struct.pack("<IIII", int(ts), int((ts - int(ts)) * 1_000_000), len(body), len(body))
    return header + body


def write_pcap(path: str, advertisements: Iterable[Advertisement], redact: bool = False) -> int:
    redactor = Redactor(enabled=redact)
    count = 0
    with open(path, "wb") as fh:
        fh.write(pcap_global_header())
        for adv in advertisements:
            fh.write(pcap_record(adv, redactor))
            count += 1
    return count


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def devices_to_json(
    devices: list[dict[str, Any]],
    redact: bool = False,
    metadata: dict[str, Any] | None = None,
) -> str:
    redactor = Redactor(enabled=redact)
    out = []
    for d in devices:
        snap = dict(d.get("snapshot") or d)
        if redact:
            snap = _redact_snapshot(snap, redactor)
        out.append(snap)
    doc = {
        "tool": "ble-monitor",
        "exported_at": time.time(),
        "redacted": redact,
        "redaction_note": redactor.describe(),
        "device_count": len(out),
        "metadata": metadata or {},
        "devices": out,
    }
    return json.dumps(doc, indent=2, default=str)


def _scrub(value: Any, secrets: list[tuple[str, str]]) -> Any:
    """Recursively replace every occurrence of a secret string anywhere in a
    nested structure.

    Redacting only the dedicated ``address`` and ``names`` fields is not enough:
    the same values are quoted verbatim inside human-readable prose — matcher
    evidence ("advertises the name “Sam's iPhone”"), exposure reasons and
    continuity evidence all embed them. Anything less than a full walk leaks.
    """
    if isinstance(value, str):
        for secret, replacement in secrets:
            if secret and secret in value:
                value = value.replace(secret, replacement)
        return value
    if isinstance(value, dict):
        return {k: _scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, secrets) for v in value]
    return value


def _redact_snapshot(snap: dict[str, Any], redactor: Redactor) -> dict[str, Any]:
    secrets: list[tuple[str, str]] = []
    for address in [snap.get("address"), snap.get("key"), *(snap.get("addresses_seen") or [])]:
        if address:
            secrets.append((str(address), redactor.address(str(address))))
    # A device name is very often a person's own name.
    for name in snap.get("names") or []:
        if name:
            secrets.append((str(name), "<redacted>"))
    # Longest first, so a name that contains another is replaced whole.
    secrets.sort(key=lambda pair: len(pair[0]), reverse=True)

    snap = _scrub(dict(snap), secrets)
    if snap.get("names"):
        snap["names"] = ["<redacted>" for _ in snap["names"]]
        snap["display_name"] = snap.get("category", "device")
    return snap


def _raw_hex(raw: object, redact: bool) -> str:
    if raw is None:
        return ""
    data = bytes(raw)
    if redact:
        data = redact_raw_payload(data)
    return data.hex()


def observations_to_json(rows: list[dict[str, Any]], redact: bool = False) -> str:
    redactor = Redactor(enabled=redact)
    out = []
    for r in rows:
        out.append(
            {
                "timestamp": r.get("ts"),
                "address": redactor.address(str(r.get("address", ""))),
                "device_key": redactor.address(str(r.get("device_key", ""))),
                "rssi": r.get("rssi"),
                "channel": r.get("channel"),
                "pdu_type": r.get("pdu_type"),
                "phy": r.get("phy"),
                "scan_response": bool(r.get("scan_rsp")),
                "source": r.get("source"),
                "raw": _raw_hex(r.get("raw"), redact),
            }
        )
    return json.dumps(
        {
            "tool": "ble-monitor",
            "exported_at": time.time(),
            "redacted": redact,
            "redaction_note": redactor.describe(),
            "observation_count": len(out),
            "observations": out,
        },
        indent=2,
        default=str,
    )


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

DEVICE_CSV_COLUMNS = [
    "key",
    "address",
    "address_type",
    "address_is_rotating",
    "display_name",
    "category",
    "confidence",
    "is_tracker",
    "first_seen",
    "last_seen",
    "duration_seconds",
    "packet_count",
    "advertising_rate",
    "rssi",
    "proximity",
    "exposure_score",
    "exposure_band",
    "company_names",
    "service_uuids",
    "protocols",
]


def devices_to_csv(devices: list[dict[str, Any]], redact: bool = False) -> str:
    redactor = Redactor(enabled=redact)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=DEVICE_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for d in devices:
        snap = dict(d.get("snapshot") or d)
        if redact:
            snap = _redact_snapshot(snap, redactor)
        ident = snap.get("identification") or {}
        best = (ident.get("best") or {}) if isinstance(ident, dict) else {}
        exposure = snap.get("exposure") or {}
        writer.writerow(
            {
                "key": snap.get("key"),
                "address": snap.get("address"),
                "address_type": snap.get("address_type"),
                "address_is_rotating": snap.get("address_is_rotating"),
                "display_name": snap.get("display_name"),
                "category": snap.get("category"),
                "confidence": best.get("confidence"),
                "is_tracker": snap.get("is_tracker"),
                "first_seen": snap.get("first_seen"),
                "last_seen": snap.get("last_seen"),
                "duration_seconds": snap.get("duration"),
                "packet_count": snap.get("packet_count"),
                "advertising_rate": snap.get("advertising_rate"),
                "rssi": snap.get("rssi_smoothed") or snap.get("rssi"),
                "proximity": snap.get("proximity"),
                "exposure_score": exposure.get("score"),
                "exposure_band": exposure.get("band"),
                "company_names": "; ".join(snap.get("company_names") or []),
                "service_uuids": "; ".join(snap.get("service_uuids") or []),
                "protocols": "; ".join((snap.get("protocols") or {}).keys()),
            }
        )
    return buf.getvalue()


OBSERVATION_CSV_COLUMNS = [
    "timestamp",
    "device_key",
    "address",
    "rssi",
    "channel",
    "pdu_type",
    "phy",
    "scan_response",
    "source",
    "raw_hex",
]


def observations_to_csv(rows: list[dict[str, Any]], redact: bool = False) -> str:
    redactor = Redactor(enabled=redact)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=OBSERVATION_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow(
            {
                "timestamp": r.get("ts"),
                "device_key": redactor.address(str(r.get("device_key", ""))),
                "address": redactor.address(str(r.get("address", ""))),
                "rssi": r.get("rssi"),
                "channel": r.get("channel"),
                "pdu_type": r.get("pdu_type"),
                "phy": r.get("phy"),
                "scan_response": bool(r.get("scan_rsp")),
                "source": r.get("source"),
                "raw_hex": _raw_hex(r.get("raw"), redact),
            }
        )
    return buf.getvalue()
