"""Link-layer and connection decoding — only reachable with sniffer hardware.

A host Bluetooth adapter cannot give you any of this. Once a sniffer is
following a connection it delivers data-channel PDUs, and this module turns
them into LL control opcodes, L2CAP frames and ATT (GATT) operations.

The honest framing the UI must carry: once a connection is encrypted, we see
that traffic is flowing, how much, and in which direction, but not what it
says. That is itself worth showing — it is the difference between "this device
is chatting privately" and "this device is chatting in the clear".
"""

from __future__ import annotations

import struct
from typing import Any

from blemon.decode.assigned import characteristic_name, service_name
from blemon.models import LinkEvent

# ---------------------------------------------------------------------------
# Link Layer control PDUs (LLID 0b11)
# ---------------------------------------------------------------------------

LL_CONTROL_OPCODES: dict[int, str] = {
    0x00: "LL_CONNECTION_UPDATE_IND",
    0x01: "LL_CHANNEL_MAP_IND",
    0x02: "LL_TERMINATE_IND",
    0x03: "LL_ENC_REQ",
    0x04: "LL_ENC_RSP",
    0x05: "LL_START_ENC_REQ",
    0x06: "LL_START_ENC_RSP",
    0x07: "LL_UNKNOWN_RSP",
    0x08: "LL_FEATURE_REQ",
    0x09: "LL_FEATURE_RSP",
    0x0A: "LL_PAUSE_ENC_REQ",
    0x0B: "LL_PAUSE_ENC_RSP",
    0x0C: "LL_VERSION_IND",
    0x0D: "LL_REJECT_IND",
    0x0E: "LL_PERIPHERAL_FEATURE_REQ",
    0x0F: "LL_CONNECTION_PARAM_REQ",
    0x10: "LL_CONNECTION_PARAM_RSP",
    0x11: "LL_REJECT_EXT_IND",
    0x12: "LL_PING_REQ",
    0x13: "LL_PING_RSP",
    0x14: "LL_LENGTH_REQ",
    0x15: "LL_LENGTH_RSP",
    0x16: "LL_PHY_REQ",
    0x17: "LL_PHY_RSP",
    0x18: "LL_PHY_UPDATE_IND",
    0x19: "LL_MIN_USED_CHANNELS_IND",
    0x1A: "LL_CTE_REQ",
    0x1B: "LL_CTE_RSP",
    0x1C: "LL_PERIODIC_SYNC_IND",
    0x1D: "LL_CLOCK_ACCURACY_REQ",
    0x1E: "LL_CLOCK_ACCURACY_RSP",
    0x1F: "LL_CIS_REQ",
    0x20: "LL_CIS_RSP",
    0x21: "LL_CIS_IND",
    0x22: "LL_CIS_TERMINATE_IND",
}

BT_VERSIONS: dict[int, str] = {
    6: "4.0",
    7: "4.1",
    8: "4.2",
    9: "5.0",
    10: "5.1",
    11: "5.2",
    12: "5.3",
    13: "5.4",
    14: "6.0",
}

# ---------------------------------------------------------------------------
# ATT (GATT) opcodes
# ---------------------------------------------------------------------------

ATT_OPCODES: dict[int, str] = {
    0x01: "Error Response",
    0x02: "Exchange MTU Request",
    0x03: "Exchange MTU Response",
    0x04: "Find Information Request",
    0x05: "Find Information Response",
    0x06: "Find By Type Value Request",
    0x07: "Find By Type Value Response",
    0x08: "Read By Type Request",
    0x09: "Read By Type Response",
    0x0A: "Read Request",
    0x0B: "Read Response",
    0x0C: "Read Blob Request",
    0x0D: "Read Blob Response",
    0x0E: "Read Multiple Request",
    0x0F: "Read Multiple Response",
    0x10: "Read By Group Type Request",
    0x11: "Read By Group Type Response",
    0x12: "Write Request",
    0x13: "Write Response",
    0x16: "Prepare Write Request",
    0x17: "Prepare Write Response",
    0x18: "Execute Write Request",
    0x19: "Execute Write Response",
    0x1B: "Handle Value Notification",
    0x1D: "Handle Value Indication",
    0x1E: "Handle Value Confirmation",
    0x52: "Write Command",
    0xD2: "Signed Write Command",
}

ATT_ERRORS: dict[int, str] = {
    0x01: "Invalid Handle",
    0x02: "Read Not Permitted",
    0x03: "Write Not Permitted",
    0x05: "Insufficient Authentication",
    0x06: "Request Not Supported",
    0x08: "Insufficient Authorization",
    0x0A: "Attribute Not Found",
    0x0C: "Insufficient Encryption Key Size",
    0x0E: "Unlikely Error",
    0x0F: "Insufficient Encryption",
    0x11: "Insufficient Resources",
}

SMP_OPCODES: dict[int, str] = {
    0x01: "Pairing Request",
    0x02: "Pairing Response",
    0x03: "Pairing Confirm",
    0x04: "Pairing Random",
    0x05: "Pairing Failed",
    0x06: "Encryption Information",
    0x07: "Central Identification",
    0x08: "Identity Information",
    0x09: "Identity Address Information",
    0x0A: "Signing Information",
    0x0B: "Security Request",
    0x0C: "Pairing Public Key",
    0x0D: "Pairing DHKey Check",
    0x0E: "Pairing Keypress Notification",
}

SMP_IO_CAPS = {
    0x00: "DisplayOnly",
    0x01: "DisplayYesNo",
    0x02: "KeyboardOnly",
    0x03: "NoInputNoOutput",
    0x04: "KeyboardDisplay",
}

L2CAP_CHANNELS = {0x0004: "ATT", 0x0005: "LE Signalling", 0x0006: "SMP"}


def decode_data_pdu(
    body: bytes, timestamp: float, direction: str, encrypted: bool = False
) -> LinkEvent:
    """Decode one data-channel PDU into a :class:`LinkEvent`."""
    if len(body) < 2:
        return LinkEvent(timestamp, "data", summary="empty PDU", direction=direction, raw=body)

    llid = body[0] & 0x03
    length = body[1]
    payload = body[2 : 2 + length]

    if encrypted:
        return LinkEvent(
            timestamp,
            "data",
            summary=f"{length} bytes of encrypted data ({direction})",
            detail={"llid": llid, "length": length},
            encrypted=True,
            direction=direction,
            raw=body,
        )

    if llid == 0x03:
        return _ll_control(payload, timestamp, direction, body)
    if llid == 0x01 and length == 0:
        return LinkEvent(
            timestamp, "data", summary="empty packet (keep-alive)", direction=direction, raw=body
        )
    if llid in (0x01, 0x02):
        return _l2cap(payload, timestamp, direction, body, continuation=(llid == 0x01))

    return LinkEvent(
        timestamp,
        "data",
        summary=f"LLID {llid}, {length} bytes",
        direction=direction,
        raw=body,
    )


def _ll_control(payload: bytes, ts: float, direction: str, raw: bytes) -> LinkEvent:
    if not payload:
        return LinkEvent(ts, "data", summary="empty LL control PDU", direction=direction, raw=raw)
    opcode = payload[0]
    name = LL_CONTROL_OPCODES.get(opcode, f"LL control 0x{opcode:02X}")
    detail: dict[str, Any] = {"opcode": opcode, "name": name}
    kind = "data"
    summary = name

    if opcode == 0x0C and len(payload) >= 6:  # LL_VERSION_IND
        version = payload[1]
        company = struct.unpack("<H", payload[2:4])[0]
        sub = struct.unpack("<H", payload[4:6])[0]
        detail.update(
            {
                "bluetooth_version": BT_VERSIONS.get(version, f"raw {version}"),
                "company_id": company,
                "subversion": sub,
            }
        )
        summary = f"Version exchange: Bluetooth {BT_VERSIONS.get(version, version)}"
    elif opcode == 0x03:  # LL_ENC_REQ
        kind = "encryption"
        summary = "Encryption requested — everything after this is opaque to us"
    elif opcode == 0x05:  # LL_START_ENC_REQ
        kind = "encryption"
        summary = "Encryption starting"
    elif opcode == 0x06:  # LL_START_ENC_RSP
        kind = "encryption"
        summary = "Encryption established"
    elif opcode == 0x02:  # LL_TERMINATE_IND
        kind = "disconnect"
        reason = payload[1] if len(payload) > 1 else None
        detail["reason_code"] = reason
        summary = f"Connection terminated (reason 0x{reason:02X})" if reason else "Connection terminated"
    elif opcode == 0x14 and len(payload) >= 5:  # LL_LENGTH_REQ
        rx, rx_t = struct.unpack("<HH", payload[1:5])
        detail.update({"max_rx_octets": rx, "max_rx_time": rx_t})
        summary = f"Data length extension requested ({rx} octets)"
    elif opcode == 0x01 and len(payload) >= 6:  # LL_CHANNEL_MAP_IND
        chmap = payload[1:6]
        used = sum(bin(b).count("1") for b in chmap)
        detail.update({"channel_map": chmap.hex(), "channels_in_use": used})
        summary = f"Channel map update — {used} of 37 data channels in use"

    return LinkEvent(ts, kind, summary=summary, detail=detail, direction=direction, raw=raw)


def _l2cap(payload: bytes, ts: float, direction: str, raw: bytes, continuation: bool) -> LinkEvent:
    if continuation:
        return LinkEvent(
            ts,
            "data",
            summary=f"L2CAP continuation fragment, {len(payload)} bytes",
            direction=direction,
            raw=raw,
        )
    if len(payload) < 4:
        return LinkEvent(
            ts, "data", summary=f"short L2CAP frame ({len(payload)} bytes)", direction=direction, raw=raw
        )
    plen, cid = struct.unpack("<HH", payload[:4])
    body = payload[4 : 4 + plen]
    channel = L2CAP_CHANNELS.get(cid, f"CID 0x{cid:04X}")

    if cid == 0x0004:
        return _att(body, ts, direction, raw)
    if cid == 0x0006:
        return _smp(body, ts, direction, raw)
    return LinkEvent(
        ts,
        "data",
        summary=f"L2CAP on {channel}, {plen} bytes",
        detail={"cid": cid, "length": plen, "payload": body.hex()},
        direction=direction,
        raw=raw,
    )


def _att(body: bytes, ts: float, direction: str, raw: bytes) -> LinkEvent:
    if not body:
        return LinkEvent(ts, "gatt", summary="empty ATT PDU", direction=direction, raw=raw)
    op = body[0]
    name = ATT_OPCODES.get(op, f"ATT opcode 0x{op:02X}")
    detail: dict[str, Any] = {"opcode": op, "operation": name}
    summary = name

    if op == 0x01 and len(body) >= 5:
        req_op = body[1]
        handle = struct.unpack("<H", body[2:4])[0]
        err = body[4]
        detail.update(
            {
                "failed_operation": ATT_OPCODES.get(req_op, f"0x{req_op:02X}"),
                "handle": handle,
                "error": ATT_ERRORS.get(err, f"0x{err:02X}"),
            }
        )
        summary = f"Error: {detail['error']} on handle 0x{handle:04X}"

    elif op in (0x02, 0x03) and len(body) >= 3:
        mtu = struct.unpack("<H", body[1:3])[0]
        detail["mtu"] = mtu
        summary = f"MTU {'request' if op == 0x02 else 'response'}: {mtu} bytes"
        return LinkEvent(ts, "mtu", summary=summary, detail=detail, direction=direction, raw=raw)

    elif op in (0x0A, 0x0C) and len(body) >= 3:
        handle = struct.unpack("<H", body[1:3])[0]
        detail["handle"] = handle
        summary = f"Read handle 0x{handle:04X}"

    elif op in (0x12, 0x52) and len(body) >= 3:
        handle = struct.unpack("<H", body[1:3])[0]
        value = body[3:]
        detail.update({"handle": handle, "value": value.hex(), "value_ascii": _printable(value)})
        summary = f"Write handle 0x{handle:04X} = {value.hex()}"

    elif op in (0x1B, 0x1D) and len(body) >= 3:
        handle = struct.unpack("<H", body[1:3])[0]
        value = body[3:]
        detail.update({"handle": handle, "value": value.hex(), "value_ascii": _printable(value)})
        kind = "notification" if op == 0x1B else "indication"
        summary = f"{kind.capitalize()} from handle 0x{handle:04X}: {value.hex()}"

    elif op == 0x10 and len(body) >= 7:
        start, end = struct.unpack("<HH", body[1:5])
        uuid = body[5:][::-1].hex().upper()
        detail.update({"start_handle": start, "end_handle": end, "group_type": uuid})
        summary = "Discovering services"

    elif op == 0x11 and len(body) >= 2:
        item_len = body[1]
        found = []
        for off in range(2, len(body) - item_len + 1, item_len):
            item = body[off : off + item_len]
            if len(item) >= 6:
                s, e = struct.unpack("<HH", item[:4])
                uuid = item[4:][::-1].hex().upper()
                found.append({"start": s, "end": e, "uuid": uuid, "name": service_name(uuid)})
        detail["services"] = found
        names = ", ".join(f["name"] or f["uuid"] for f in found) or "none"
        summary = f"Services found: {names}"

    elif op == 0x09 and len(body) >= 2:
        item_len = body[1]
        chars = []
        for off in range(2, len(body) - item_len + 1, item_len):
            item = body[off : off + item_len]
            if len(item) >= 5:
                handle = struct.unpack("<H", item[:2])[0]
                props = item[2]
                value_handle = struct.unpack("<H", item[3:5])[0]
                uuid = item[5:][::-1].hex().upper() if len(item) > 5 else ""
                chars.append(
                    {
                        "handle": handle,
                        "value_handle": value_handle,
                        "properties": _char_props(props),
                        "uuid": uuid,
                        "name": characteristic_name(uuid) if uuid else None,
                    }
                )
        detail["characteristics"] = chars
        names = ", ".join(c["name"] or c["uuid"] for c in chars) or "none"
        summary = f"Characteristics found: {names}"

    elif op == 0x0B:
        value = body[1:]
        detail.update({"value": value.hex(), "value_ascii": _printable(value)})
        summary = f"Read response: {value.hex()}"

    return LinkEvent(ts, "gatt", summary=summary, detail=detail, direction=direction, raw=raw)


def _smp(body: bytes, ts: float, direction: str, raw: bytes) -> LinkEvent:
    if not body:
        return LinkEvent(ts, "encryption", summary="empty SMP PDU", direction=direction, raw=raw)
    op = body[0]
    name = SMP_OPCODES.get(op, f"SMP 0x{op:02X}")
    detail: dict[str, Any] = {"opcode": op, "operation": name}
    summary = f"Pairing: {name}"

    if op in (0x01, 0x02) and len(body) >= 6:
        io_cap = body[1]
        oob = body[2]
        auth = body[3]
        detail.update(
            {
                "io_capability": SMP_IO_CAPS.get(io_cap, f"0x{io_cap:02X}"),
                "oob_data": bool(oob),
                "bonding": bool(auth & 0x03),
                "mitm_protection": bool(auth & 0x04),
                "secure_connections": bool(auth & 0x08),
                "keypress": bool(auth & 0x10),
            }
        )
        sc = "LE Secure Connections" if auth & 0x08 else "legacy pairing"
        mitm = "with" if auth & 0x04 else "without"
        summary = f"Pairing {name.split()[1].lower()}: {sc}, {mitm} MITM protection"

    elif op == 0x05 and len(body) >= 2:
        detail["reason"] = body[1]
        summary = f"Pairing failed (reason 0x{body[1]:02X})"

    return LinkEvent(
        ts, "encryption", summary=summary, detail=detail, direction=direction, raw=raw
    )


def _char_props(props: int) -> list[str]:
    names = [
        (0x01, "broadcast"),
        (0x02, "read"),
        (0x04, "write-without-response"),
        (0x08, "write"),
        (0x10, "notify"),
        (0x20, "indicate"),
        (0x40, "authenticated-signed-write"),
        (0x80, "extended"),
    ]
    return [n for m, n in names if props & m]


def _printable(data: bytes) -> str | None:
    if not data:
        return None
    text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data)
    printable = sum(1 for b in data if 0x20 <= b < 0x7F)
    return text if printable >= len(data) * 0.7 else None


def explain(event: LinkEvent) -> str:
    """Plain-English gloss for a link event."""
    if event.encrypted:
        return (
            "Encrypted traffic is flowing. We can see that the two devices are talking and "
            "how much they are saying, but not what. This is what a well-behaved connection "
            "should look like."
        )
    if event.kind == "encryption":
        if "Secure Connections" in event.summary:
            return (
                "These two devices are pairing using LE Secure Connections, the modern "
                "elliptic-curve scheme. An eavesdropper who missed nothing still cannot "
                "derive the key."
            )
        if "legacy" in event.summary:
            return (
                "These two devices are pairing using legacy pairing. If a listener captures "
                "the whole exchange, the key can be recovered — this is the weak mode, and "
                "seeing it is genuinely interesting."
            )
        return "The connection is setting up encryption. Traffic after this point is opaque."
    if event.kind == "mtu":
        return (
            "The two devices are agreeing on how large each message can be. Nothing sensitive, "
            "but it marks the beginning of a real conversation."
        )
    if event.kind == "gatt":
        detail = event.detail or {}
        if "services" in detail:
            return (
                "One device is asking the other what it can do, and getting a list of services "
                "back. This is the handshake that reveals what a device actually is."
            )
        if detail.get("value_ascii"):
            return (
                f"Unencrypted GATT traffic carrying readable text: “{detail['value_ascii']}”. "
                "This is content passing in the clear between two devices near you."
            )
        if "Notification" in event.summary or "Indication" in event.summary:
            return (
                "The peripheral is pushing a value to the phone or computer it is connected to "
                "— a sensor reading, a button press, a status change — and it is unencrypted."
            )
        return "Unencrypted GATT traffic. The operation and the data are both visible."
    if event.kind == "disconnect":
        return "The connection has ended."
    return event.summary
