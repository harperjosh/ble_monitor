"""Nordic nRF Sniffer support — nRF52840 dongles and development kits.

This is the *secondary* sniffer path. Sniffle on TI silicon is the one to buy:
it captures all three advertising channels for a target, follows connections
more reliably, and its protocol is simpler to drive. The nRF Sniffer is here
because a lot of people already own an nRF52840 dongle.

Two things to know about it:

* It listens on **one advertising channel at a time**, so you see roughly a
  third of any device's advertisements unless you are following a target.
* Nordic's firmware is a separate download from the nRF Sniffer for Bluetooth
  LE package, and the dongle must be flashed with it — a stock nRF52840 dongle
  will not respond. ``blemon doctor`` says so and links the instructions.
"""

from __future__ import annotations

import asyncio
import struct
import threading
import time
from dataclasses import dataclass

from blemon.capture.base import BackendStatus, CaptureError, QueueBackend, register
from blemon.capture.llparse import parse_adv_pdu
from blemon.decode.link import decode_data_pdu
from blemon.models import (
    AddressType,
    Advertisement,
    Capabilities,
    LinkEvent,
    PduType,
    classify_address,
)

SLIP_START = 0xAB
SLIP_END = 0xBC
SLIP_ESC = 0xCD

PROTOCOL_VERSION = 3
HEADER_LENGTH = 6

REQ_FOLLOW = 0x00
EVENT_FOLLOW = 0x01
EVENT_PACKET_ADV_PDU = 0x02
EVENT_CONNECT = 0x05
EVENT_PACKET = 0x06
REQ_SCAN_CONT = 0x07
EVENT_DISCONNECT = 0x09
PING_REQ = 0x0D
PING_RESP = 0x0E
SWITCH_BAUD_RATE_REQ = 0x13
SET_ADV_CHANNEL_HOP_SEQ = 0x17
GO_IDLE = 0xFE

PHY_NAMES = {0: "1M", 1: "2M", 2: "Coded", 3: "Coded"}

#: Nordic dongles and dev kits, by USB identity: (name, firmware state). The
#: firmware state is derived from the PID so doctor branches on a structured
#: value rather than substring-matching presentation text.
NORDIC_IDS: dict[tuple[int, int], tuple[str, str]] = {
    (0x1915, 0x520F): ("nRF52840 Dongle (Nordic bootloader)", "bootloader"),
    (0x1915, 0xC00A): ("nRF52840 Dongle (Sniffer firmware)", "sniffer"),
    (0x1366, 0x0105): ("nRF52840 DK (J-Link)", "unknown"),
    (0x1366, 0x1015): ("nRF52840 DK (J-Link)", "unknown"),
}


@dataclass
class DetectedNordic:
    port: str
    description: str
    vid: int
    pid: int
    #: "sniffer" | "bootloader" | "unknown" — whether it is running nRF Sniffer
    #: firmware, as far as the USB identity can tell.
    firmware: str = "unknown"


def detect_nordic() -> list[DetectedNordic]:
    try:
        from serial.tools import list_ports
    except ImportError:
        return []
    out = []
    for port in list_ports.comports():
        if port.vid is None or port.pid is None:
            continue
        entry = NORDIC_IDS.get((port.vid, port.pid))
        if entry:
            name, firmware = entry
            out.append(
                DetectedNordic(
                    port=port.device,
                    description=f"{name} on {port.device}",
                    vid=port.vid,
                    pid=port.pid,
                    firmware=firmware,
                )
            )
    return out


# Nordic's nRF Sniffer SLIP variant escapes a special byte as ESC followed by
# (byte + 1), NOT the RFC-1055 XOR-0x20 convention: 0xAB->CD AC, 0xBC->CD BD,
# 0xCD->CD CE. Using XOR here silently corrupts any frame whose payload contains
# a 0xAB/0xBC/0xCD byte (common in MAC/counter fields), in both directions.
def _slip_unescape(byte: int) -> int:
    return (byte - 1) & 0xFF


def _slip_escape(byte: int) -> int:
    return (byte + 1) & 0xFF


def slip_encode(payload: bytes) -> bytes:
    out = bytearray([SLIP_START])
    for byte in payload:
        if byte in (SLIP_START, SLIP_END, SLIP_ESC):
            out.append(SLIP_ESC)
            out.append(_slip_escape(byte))
        else:
            out.append(byte)
    out.append(SLIP_END)
    return bytes(out)


class SlipDecoder:
    """Incremental SLIP framing decoder."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._in_frame = False
        self._escaped = False

    def feed(self, data: bytes) -> list[bytes]:
        frames: list[bytes] = []
        for byte in data:
            if not self._in_frame:
                if byte == SLIP_START:
                    self._in_frame = True
                    self._buffer.clear()
                    self._escaped = False
                continue
            if self._escaped:
                self._buffer.append(_slip_unescape(byte))
                self._escaped = False
            elif byte == SLIP_ESC:
                self._escaped = True
            elif byte == SLIP_END:
                frames.append(bytes(self._buffer))
                self._in_frame = False
            elif byte == SLIP_START:
                self._buffer.clear()  # a restart mid-frame; drop the partial
            else:
                self._buffer.append(byte)
        return frames


class NrfSnifferBackend(QueueBackend):
    name = "nrf"

    def __init__(
        self,
        port: str | None = None,
        baudrate: int = 1_000_000,
        channel: int = 37,
        **_: object,
    ) -> None:
        super().__init__()
        self.port = port
        self.baudrate = baudrate
        self.channel = channel if channel in (37, 38, 39) else 37
        self._serial = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._counter = 0
        self._hardware = "unknown"
        self._followed: str | None = None
        self._in_connection = False
        self._saw_any_packet = False

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(
            name=f"Nordic nRF Sniffer ({self._hardware})",
            description=f"nRF52840 sniffer on {self.port or 'auto-detected port'}.",
            advertising=True,
            extended_advertising=True,
            real_mac_addresses=True,
            raw_payloads=True,
            scan_responses=True,
            connection_following=True,
            three_channel_advertising=False,
            coded_phy=True,
            two_m_phy=True,
            can_transmit=False,
            channel_reporting=True,
            caveats=[
                f"Listening on advertising channel {self.channel} only. A device rotates "
                "across 37, 38 and 39, so expect to see roughly a third of its "
                "advertisements. Sniffle on TI hardware can cover all three for a target.",
                "One sniffer follows one connection at a time.",
                "Requires Nordic's nRF Sniffer firmware. A stock dongle will not respond — "
                "`blemon doctor` has the flashing instructions.",
                "Encrypted connections stay encrypted.",
            ],
        )

    @staticmethod
    def available() -> tuple[bool, str]:
        try:
            import serial  # noqa: F401
        except ImportError:
            return False, "pyserial is not installed (pip install pyserial)"
        if not detect_nordic():
            return False, "no Nordic nRF52840 sniffer detected on any serial port"
        return True, ""

    async def start(self) -> None:
        try:
            import serial
        except ImportError as exc:
            raise CaptureError("pyserial is required.", remedy="pip install pyserial") from exc

        self._loop = asyncio.get_running_loop()
        if self.port is None:
            found = detect_nordic()
            if not found:
                raise CaptureError(
                    "No Nordic sniffer found.",
                    remedy=(
                        "Plug in an nRF52840 dongle flashed with Nordic's nRF Sniffer for "
                        "Bluetooth LE firmware. `blemon doctor` has the flashing steps."
                    ),
                )
            self.port = found[0].port
            self._hardware = found[0].description
        else:
            self._hardware = f"serial port {self.port}"

        try:
            self._serial = serial.Serial(self.port, self.baudrate, timeout=1.0)
        except Exception as exc:
            raise CaptureError(
                f"Could not open {self.port}: {exc}",
                remedy="On Linux add yourself to the `dialout` group, then log out and in.",
            ) from exc

        self._send(GO_IDLE)
        self._send(SET_ADV_CHANNEL_HOP_SEQ, bytes([1, self.channel]))
        self._send(REQ_SCAN_CONT)
        self._send(PING_REQ)

        await super().start()
        self._status = BackendStatus(
            "scanning",
            f"Sniffing advertising channel {self.channel} via {self._hardware}.",
            {"port": self.port, "channel": self.channel},
        )
        self._thread = threading.Thread(target=self._reader, name="blemon-nrf", daemon=True)
        self._thread.start()

    async def stop(self) -> None:
        await super().stop()
        if self._serial is not None:
            try:
                self._send(GO_IDLE)
                self._serial.close()
            except Exception:
                pass
            self._serial = None

    def _send(self, packet_id: int, payload: bytes = b"") -> None:
        if self._serial is None:
            return
        self._counter = (self._counter + 1) & 0xFFFF
        header = struct.pack(
            "<BBBHB",
            HEADER_LENGTH,
            len(payload),
            PROTOCOL_VERSION,
            self._counter,
            packet_id,
        )
        self._serial.write(slip_encode(header + payload))

    async def follow(self, address: str, address_type: str | None = None) -> bool:
        if self._serial is None:
            return False
        try:
            mac = bytes(int(x, 16) for x in address.upper().split(":"))[::-1]
        except ValueError:
            return False
        if len(mac) != 6:
            return False
        # The firmware filters on address AND address type, so following a
        # public-address peripheral with the type hardcoded to random never
        # matches. Use the known type; when it is unknown, fall back to the
        # top-bit classification (a public MAC's bits classify as UNKNOWN, which
        # we treat as public rather than forcing random).
        if address_type == "public":
            type_byte = 0x00
        elif address_type in ("random_static", "resolvable_private", "non_resolvable_private"):
            type_byte = 0x01
        else:
            type_byte = 0x01 if classify_address(address, True).is_rotating or \
                classify_address(address, True) is AddressType.RANDOM_STATIC else 0x00
        # addr(6) + addr_type(1) + follow_only_advertisements(1) + follow_only_legacy(1)
        self._send(REQ_FOLLOW, mac + bytes([type_byte, 0x00, 0x00]))
        self._followed = address.upper()
        self.emit(
            BackendStatus("following", f"Aimed at {address}.", {"target": address})
        )
        return True

    async def unfollow(self) -> None:
        if self._serial is None:
            return
        self._send(REQ_SCAN_CONT)
        self._followed = None
        self.emit(BackendStatus("scanning", "Spotlight released."))

    def _reader(self) -> None:
        decoder = SlipDecoder()
        loop = self._loop
        assert loop is not None
        deadline = time.time() + 8.0
        while self.running and self._serial is not None:
            try:
                chunk = self._serial.read(1024)
            except Exception:
                if self.running:
                    self.emit_threadsafe(
                        loop, BackendStatus("error", "Lost contact with the nRF sniffer.")
                    )
                return
            if not chunk:
                if not self._saw_any_packet and time.time() > deadline:
                    self.emit_threadsafe(
                        loop,
                        BackendStatus(
                            "error",
                            "The dongle is connected but has sent nothing. It is probably "
                            "not running Nordic's nRF Sniffer firmware — see `blemon doctor`.",
                        ),
                    )
                    deadline = time.time() + 60.0
                continue
            for frame in decoder.feed(chunk):
                self._saw_any_packet = True
                try:
                    self._handle_frame(loop, frame)
                except Exception:
                    continue

    def _handle_frame(self, loop: asyncio.AbstractEventLoop, frame: bytes) -> None:
        if len(frame) < HEADER_LENGTH:
            return
        header_len, payload_len, _version, _counter, packet_id = struct.unpack(
            "<BBBHB", frame[:HEADER_LENGTH]
        )
        payload = frame[header_len : header_len + payload_len]

        if packet_id in (EVENT_PACKET, EVENT_PACKET_ADV_PDU):
            self._handle_packet(loop, payload)
        elif packet_id == EVENT_CONNECT:
            self._in_connection = True
            self.emit_threadsafe(
                loop,
                BackendStatus(
                    "following",
                    "Connection established — following it onto the data channels. "
                    "Advertising capture is paused until it ends.",
                    {"target": self._followed},
                ),
            )
        elif packet_id == EVENT_DISCONNECT:
            self._in_connection = False
            self.emit_threadsafe(
                loop,
                LinkEvent(
                    timestamp=time.time(),
                    kind="disconnect",
                    address=self._followed,
                    summary="Connection ended.",
                ),
            )

    def _handle_packet(self, loop: asyncio.AbstractEventLoop, payload: bytes) -> None:
        if len(payload) < 10:
            return
        sub_len = payload[0]
        flags = payload[1]
        channel = payload[2]
        rssi = -payload[3]
        phy = PHY_NAMES.get((flags >> 4) & 0x03, "1M")
        ble = payload[sub_len:]

        crc_ok = bool(flags & 0x01)
        direction = "peripheral" if (flags & 0x02) else "central"
        encrypted = bool(flags & 0x04)
        if not crc_ok:
            return
        if len(ble) < 6:
            return

        pdu = ble[4:-3] if len(ble) > 7 else ble[4:]  # strip access address and CRC
        now = time.time()

        if channel in (37, 38, 39):
            parsed = parse_adv_pdu(pdu)
            if parsed is None or parsed.address is None:
                return
            if parsed.pdu_type is PduType.CONNECT_IND:
                self.emit_threadsafe(
                    loop,
                    LinkEvent(
                        timestamp=now,
                        kind="connect",
                        address=parsed.address,
                        summary=f"{parsed.target_address} is connecting to {parsed.address}",
                        detail={"channel": channel},
                        raw=pdu,
                    ),
                )
            self.emit_threadsafe(
                loop,
                Advertisement(
                    address=parsed.address,
                    timestamp=now,
                    rssi=rssi,
                    address_type=classify_address(parsed.address, parsed.tx_random),
                    raw=parsed.data,
                    channel=channel,
                    pdu_type=parsed.pdu_type,
                    phy=parsed.aux_phy or phy,
                    scan_response=parsed.pdu_type is PduType.SCAN_RSP,
                    connectable=parsed.connectable,
                    tx_power_adv=parsed.tx_power,
                    source="nrf",
                ),
            )
        else:
            event = decode_data_pdu(pdu, now, direction, encrypted=encrypted)
            event.address = self._followed
            event.detail.setdefault("channel", channel)
            event.detail.setdefault("rssi", rssi)
            self.emit_threadsafe(loop, event)



register("nrf", NrfSnifferBackend, priority=20)
