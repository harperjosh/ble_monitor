"""Bluetooth link-layer PDU parsing.

Sniffer hardware hands over whole link-layer packets rather than the cooked
advertising reports a host controller produces. That is strictly more
information — the PDU type, both address bits, the extended-advertising header
and the true channel are all present — so it gets its own parser.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from blemon.models import PduType

ADV_PDU_TYPES = {
    0x0: PduType.ADV_IND,
    0x1: PduType.ADV_DIRECT_IND,
    0x2: PduType.ADV_NONCONN_IND,
    0x3: PduType.SCAN_REQ,
    0x4: PduType.SCAN_RSP,
    0x5: PduType.CONNECT_IND,
    0x6: PduType.ADV_SCAN_IND,
    0x7: PduType.ADV_EXT_IND,
}

#: Extended-header field widths, in the order the spec lays them out.
EXT_HEADER_FIELDS: list[tuple[int, str, int]] = [
    (0, "adv_addr", 6),
    (1, "target_addr", 6),
    (2, "cte_info", 1),
    (3, "adi", 2),
    (4, "aux_ptr", 3),
    (5, "sync_info", 18),
    (6, "tx_power", 1),
]


@dataclass(slots=True)
class AdvPdu:
    pdu_type: PduType
    tx_random: bool
    rx_random: bool
    address: str | None
    target_address: str | None
    data: bytes
    tx_power: int | None = None
    #: True for a BT5 extended advertising PDU rather than a legacy one.
    extended: bool = False
    #: Set when an extended advertisement points at a secondary channel.
    aux_channel: int | None = None
    aux_phy: str | None = None
    connectable: bool | None = None
    parse_note: str | None = None


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw[::-1])


AUX_PHY_NAMES = {0: "1M", 1: "2M", 2: "Coded"}


def parse_adv_pdu(body: bytes) -> AdvPdu | None:
    """Parse an advertising-channel link-layer PDU.

    ``body`` starts at the PDU header byte, i.e. after the access address.
    Returns None when the packet is too short to be a PDU at all.
    """
    if len(body) < 2:
        return None
    header = body[0]
    length = body[1]
    payload = body[2 : 2 + length]

    pdu_type = ADV_PDU_TYPES.get(header & 0x0F, PduType.UNKNOWN)
    tx_random = bool(header & 0x40)
    rx_random = bool(header & 0x80)

    if pdu_type is PduType.ADV_EXT_IND:
        return _parse_extended(payload, tx_random, rx_random)

    if pdu_type in (PduType.ADV_IND, PduType.ADV_NONCONN_IND, PduType.ADV_SCAN_IND, PduType.SCAN_RSP):
        if len(payload) < 6:
            return AdvPdu(pdu_type, tx_random, rx_random, None, None, b"",
                          parse_note="truncated advertising PDU")
        return AdvPdu(
            pdu_type=pdu_type,
            tx_random=tx_random,
            rx_random=rx_random,
            address=_mac(payload[:6]),
            target_address=None,
            data=payload[6:],
            connectable=pdu_type is PduType.ADV_IND,
        )

    if pdu_type in (PduType.ADV_DIRECT_IND, PduType.CONNECT_IND, PduType.SCAN_REQ):
        if len(payload) < 12:
            return AdvPdu(pdu_type, tx_random, rx_random, None, None, b"",
                          parse_note="truncated directed PDU")
        # SCAN_REQ and CONNECT_IND put the initiator first, then the advertiser.
        if pdu_type in (PduType.CONNECT_IND, PduType.SCAN_REQ):
            initiator, advertiser = payload[:6], payload[6:12]
            return AdvPdu(
                pdu_type=pdu_type,
                tx_random=tx_random,
                rx_random=rx_random,
                address=_mac(advertiser),
                target_address=_mac(initiator),
                data=payload[12:],
                connectable=True,
            )
        return AdvPdu(
            pdu_type=pdu_type,
            tx_random=tx_random,
            rx_random=rx_random,
            address=_mac(payload[:6]),
            target_address=_mac(payload[6:12]),
            data=b"",
            connectable=True,
        )

    return AdvPdu(pdu_type, tx_random, rx_random, None, None, payload,
                  parse_note=f"unhandled PDU type 0x{header & 0x0F:X}")


def _parse_extended(payload: bytes, tx_random: bool, rx_random: bool) -> AdvPdu:
    if not payload:
        return AdvPdu(PduType.ADV_EXT_IND, tx_random, rx_random, None, None, b"",
                      extended=True, parse_note="empty extended PDU")

    ext_len = payload[0] & 0x3F
    if ext_len == 0:
        return AdvPdu(PduType.ADV_EXT_IND, tx_random, rx_random, None, None, payload[1:],
                      extended=True)

    flags = payload[1]
    cursor = 2
    fields: dict[str, bytes] = {}
    header_end = 1 + ext_len
    for bit, name, width in EXT_HEADER_FIELDS:
        if not (flags >> bit) & 1:
            continue
        if cursor + width > header_end:
            break
        fields[name] = payload[cursor : cursor + width]
        cursor += width

    address = _mac(fields["adv_addr"]) if "adv_addr" in fields else None
    target = _mac(fields["target_addr"]) if "target_addr" in fields else None
    tx_power = struct.unpack("<b", fields["tx_power"])[0] if "tx_power" in fields else None

    aux_channel = None
    aux_phy = None
    if "aux_ptr" in fields:
        raw = fields["aux_ptr"]
        aux_channel = raw[0] & 0x3F
        # Core Spec Vol 6 Part B 2.3.4.5: the Aux PHY is bits 21-23, i.e. the top
        # three bits of the third octet. Bits 1-3 belong to the 13-bit AUX Offset.
        aux_phy = AUX_PHY_NAMES.get((raw[2] >> 5) & 0x07)

    return AdvPdu(
        pdu_type=PduType.ADV_EXT_IND,
        tx_random=tx_random,
        rx_random=rx_random,
        address=address,
        target_address=target,
        data=payload[header_end:],
        tx_power=tx_power,
        extended=True,
        aux_channel=aux_channel,
        aux_phy=aux_phy,
        parse_note=(
            "extended advertisement with an auxiliary pointer — the payload continues "
            f"on channel {aux_channel}"
            if aux_channel is not None
            else None
        ),
    )
