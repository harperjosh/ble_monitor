"""Sniffle sniffer support — TI CC1352 / CC2652 hardware.

Sniffle is NCC Group's open sniffer firmware. This is the backend that turns
the tool from "what is being broadcast" into "what are these two devices
actually saying to each other", because it is the only one here that can follow
a connection onto the 37 data channels.

Hardware this speaks to (Sniffle runs on TI silicon only — an nRF52840 needs
Nordic's own sniffer, which has its own backend):

* SONOFF ZBDongle-**P** — the CC2652P one. The ZBDongle-**E** is Silicon Labs
  EFR32 and will not work, and the two look nearly identical in a listing.
* TI CC1352P7 LaunchPad, CC26x2R LaunchPad.
* CatSniffer v3.

The wire protocol is implemented here directly rather than depending on the
Sniffle CLI package, so the only runtime dependency is pyserial.

The limitation to be honest about everywhere: **one sniffer follows one
connection at a time.** Advertising capture is broad and continuous; connection
following is a spotlight you aim. Attach a second sniffer and you can aim a
second spotlight.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import struct
import threading
import time
from dataclasses import dataclass

from blemon.capture.base import BackendStatus, CaptureError, QueueBackend, register
from blemon.capture.llparse import parse_adv_pdu
from blemon.decode.link import decode_data_pdu
from blemon.models import Advertisement, Capabilities, LinkEvent, PduType, classify_address

BLE_ADV_ACCESS_ADDRESS = 0x8E89BED6
BLE_ADV_CRC_INIT = 0x555555

# Host to sniffer
CMD_CHAN_AA_PHY = 0x10
CMD_PAUSE_DONE = 0x11
CMD_RSSI_MIN = 0x12
CMD_MAC_FILTER = 0x13
CMD_ADV_HOP = 0x14
CMD_FOLLOW = 0x15
CMD_AUX_ADV = 0x16
CMD_RESET = 0x17
CMD_MARKER = 0x18
CMD_SCAN = 0x22
CMD_PHY_PRELOAD = 0x23
CMD_VERSION = 0x24
CMD_CRC_VALID = 0x26
CMD_TX_POWER = 0x27

# Sniffer to host
MSG_PACKET = 0x10
MSG_DEBUG = 0x11
MSG_MARKER = 0x12
MSG_STATE = 0x13
MSG_MEASUREMENT = 0x14

PHY_1M, PHY_2M, PHY_CODED_S8, PHY_CODED_S2 = 0, 1, 2, 3
PHY_NAMES = {0: "1M", 1: "2M", 2: "Coded", 3: "Coded"}

SNIFFER_STATES = {
    0: "static",
    1: "seeking advertisements",
    2: "hopping advertising channels",
    3: "following a connection",
    4: "paused",
    5: "initiating",
    6: "acting as central",
    7: "acting as peripheral",
    8: "advertising",
    9: "scanning",
    10: "advertising (extended)",
}

#: (vendor id, product id) -> human name, for auto-detection.
KNOWN_ADAPTERS: dict[tuple[int, int], str] = {
    (0x0451, 0xBEF3): "TI XDS110 (LaunchPad)",
    (0x10C4, 0xEA60): "SONOFF ZBDongle-P (CC2652P)",
    (0x2E8A, 0x00C0): "CatSniffer v3",
}

#: Silicon Labs CP2102 (non-N) tops out below Sniffle's usual 2 Mbaud.
CP2102_PIDS = {0xEA60, 0xEA61, 0xEA62, 0xEA63}


@dataclass
class DetectedSniffer:
    port: str
    description: str
    vid: int | None
    pid: int | None
    baudrate: int


def detect_sniffers() -> list[DetectedSniffer]:
    """Serial ports that look like Sniffle-capable hardware."""
    try:
        from serial.tools import list_ports
    except ImportError:
        return []

    found: list[DetectedSniffer] = []
    for port in list_ports.comports():
        vid, pid = port.vid, port.pid
        if vid is None or pid is None:
            continue
        name = KNOWN_ADAPTERS.get((vid, pid))
        if name is None:
            continue
        # SONOFF ships two dongles with the same silicon-labs bridge: the -P is
        # CC2652 and works, the -E is EFR32 and does not. The product string is
        # the only way to tell them apart from here.
        product = (port.product or "").lower()
        if (vid, pid) == (0x10C4, 0xEA60) and "zigbee" not in product and "sonoff" not in product:
            continue
        baud = 921600 if (vid == 0x10C4 and pid in CP2102_PIDS) else 2_000_000
        found.append(
            DetectedSniffer(
                port=port.device,
                description=f"{name} on {port.device}",
                vid=vid,
                pid=pid,
                baudrate=baud,
            )
        )
    return found


def probe_firmware(port: str, baudrate: int = 2_000_000, timeout: float = 0.4) -> str | None:
    """Best-effort: ask a detected dongle for its Sniffle firmware version.

    A device with the right USB identity is not necessarily running Sniffle — a
    factory SONOFF dongle ships with Zigbee firmware and answers nothing. This
    opens the port briefly, sends the version command, and returns the version
    string if it replies, or None if it stays silent. Always closes the port.
    """
    try:
        import serial
    except ImportError:
        return None
    ser = None
    try:
        ser = serial.Serial(port, baudrate, timeout=timeout)
        body = bytes([CMD_VERSION])
        frame = base64.b64encode(bytes([(len(body) + 3) // 3]) + body) + b"\r\n"
        ser.write(frame)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            line = ser.readline()
            if not line:
                continue
            try:
                data = base64.b64decode(line.rstrip())
            except Exception:
                continue
            # A measurement message (type 0x14) carrying a version measurement
            # (subtype 0x00) is the version reply.
            if len(data) >= 3 and data[1] == MSG_MEASUREMENT and data[2] == 0x00:
                return data[3:].decode("utf-8", errors="replace").strip("\x00").strip() or "present"
        return None
    except Exception:
        return None
    finally:
        if ser is not None:
            with contextlib.suppress(Exception):
                ser.close()


class SniffleTransport:
    """The Sniffle serial framing: base64 lines with a word-count header."""

    def __init__(self, port: str, baudrate: int = 2_000_000, timeout: float = 1.0):
        try:
            import serial
        except ImportError as exc:
            raise CaptureError(
                "pyserial is required to talk to a sniffer.",
                remedy="pip install pyserial",
            ) from exc
        try:
            self.serial = serial.Serial(port, baudrate, timeout=timeout)
        except Exception as exc:
            raise CaptureError(
                f"Could not open {port} at {baudrate} baud: {exc}",
                remedy=(
                    "Check the dongle is plugged in and that you have permission to use "
                    "the serial port. On Linux: `sudo usermod -aG dialout $USER` then log "
                    "out and back in. Run `blemon doctor` to confirm."
                ),
            ) from exc

    def close(self) -> None:
        try:
            self.serial.close()
        except Exception:
            pass

    def send(self, command: int, payload: bytes = b"") -> None:
        body = bytes([command]) + payload
        word_count = (len(body) + 3) // 3
        frame = base64.b64encode(bytes([word_count]) + body) + b"\r\n"
        self.serial.write(frame)

    def recv(self) -> tuple[int, bytes] | None:
        """Read one message. Returns (type, body), or None on timeout."""
        header = self.serial.read(6)
        if len(header) < 6:
            return None
        try:
            decoded = base64.b64decode(header[:4])
        except Exception:
            self.serial.readline()  # resynchronise on the next newline
            return None
        if len(decoded) < 2:
            return None
        word_count = decoded[0]
        rest = self.serial.read((word_count - 1) * 4) if word_count else b""
        frame = header + rest
        if frame[-2:] != b"\r\n":
            self.serial.readline()
            return None
        try:
            data = base64.b64decode(frame[:-2])
        except Exception:
            return None
        if len(data) < 2:
            return None
        return data[1], data[2:]

    def resync(self) -> None:
        """Read a whole line to realign after a framing error."""
        self.serial.readline()


class SniffleBackend(QueueBackend):
    name = "sniffle"

    def __init__(
        self,
        port: str | None = None,
        baudrate: int | None = None,
        rssi_min: int = -128,
        extended: bool = True,
        follow_connections: bool = True,
        channel: int = 37,
        target: str | None = None,
        **_: object,
    ) -> None:
        super().__init__()
        self.port = port
        self.baudrate = baudrate
        self.rssi_min = rssi_min
        self.extended = extended
        self.follow_connections = follow_connections
        self.channel = channel if channel in (37, 38, 39) else 37
        self.target = target.upper() if target else None

        self._transport: SniffleTransport | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._hardware = "unknown"
        self._firmware = "unknown"
        self._in_connection = False
        self._followed: str | None = None
        self._current_channel = self.channel
        self._current_phy = "1M"
        self._command_lock = threading.Lock()

    # -- capabilities ------------------------------------------------------

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(
            name=f"Sniffle ({self._hardware})",
            description=(
                f"External BLE sniffer on {self.port or 'auto-detected port'}, "
                f"firmware {self._firmware}."
            ),
            advertising=True,
            extended_advertising=self.extended,
            real_mac_addresses=True,
            raw_payloads=True,
            scan_responses=True,
            connection_following=self.follow_connections,
            three_channel_advertising=self.target is not None,
            coded_phy=self.extended,
            two_m_phy=True,
            can_transmit=False,
            channel_reporting=True,
            caveats=[
                "One sniffer follows one connection at a time. While it is following, "
                "broad advertising capture pauses — it is a spotlight, not a floodlight.",
                (
                    "Simultaneous capture on all three advertising channels only happens "
                    "when a target address is set. Without a target the sniffer listens on "
                    f"channel {self.channel} alone, so you will miss roughly two thirds of "
                    "advertisements from any given device."
                    if self.target is None
                    else f"Hopping 37/38/39 for target {self.target}."
                ),
                "Encrypted connections stay encrypted. You will see that traffic is "
                "flowing and how much, but not what it says.",
            ],
        )

    @staticmethod
    def available() -> tuple[bool, str]:
        try:
            import serial  # noqa: F401
        except ImportError:
            return False, "pyserial is not installed (pip install pyserial)"
        if not detect_sniffers():
            return False, "no Sniffle-compatible sniffer detected on any serial port"
        return True, ""

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()

        if self.port is None:
            found = detect_sniffers()
            if not found:
                raise CaptureError(
                    "No Sniffle-compatible sniffer found.",
                    remedy=(
                        "Plug in a SONOFF ZBDongle-P (CC2652P) or a TI CC1352P7 LaunchPad "
                        "flashed with Sniffle firmware. Note the SONOFF ZBDongle-E will not "
                        "work — it is Silicon Labs silicon, not TI. Run `blemon doctor` for "
                        "flashing instructions."
                    ),
                )
            chosen = found[0]
            self.port = chosen.port
            self.baudrate = self.baudrate or chosen.baudrate
            self._hardware = chosen.description
        else:
            self.baudrate = self.baudrate or 2_000_000
            self._hardware = f"serial port {self.port}"

        self._transport = SniffleTransport(self.port, self.baudrate)
        self._configure()

        await super().start()
        self._status = BackendStatus(
            "scanning",
            f"Sniffing advertisements on channel {self.channel} via {self._hardware}."
            + (f" Targeting {self.target} across 37/38/39." if self.target else ""),
            {"port": self.port, "hardware": self._hardware, "firmware": self._firmware},
        )
        self._thread = threading.Thread(target=self._reader, name="blemon-sniffle", daemon=True)
        self._thread.start()

    async def stop(self) -> None:
        await super().stop()
        if self._transport is not None:
            try:
                self._transport.send(CMD_RESET)
            except Exception:
                pass
            self._transport.close()
            self._transport = None

    def _configure(self) -> None:
        t = self._transport
        assert t is not None
        with self._command_lock:
            # Sync marker first: it flushes anything stale in the UART buffer.
            t.send(CMD_MARKER, b"\x40")
            t.send(
                CMD_CHAN_AA_PHY,
                struct.pack(
                    "<BLBL",
                    self.channel,
                    BLE_ADV_ACCESS_ADDRESS,
                    PHY_1M,
                    BLE_ADV_CRC_INIT,
                ),
            )
            t.send(CMD_RSSI_MIN, bytes([self.rssi_min & 0xFF]))
            t.send(CMD_PAUSE_DONE, bytes([0x00]))
            t.send(CMD_FOLLOW, bytes([0x01 if self.follow_connections else 0x00]))
            t.send(CMD_AUX_ADV, bytes([0x01 if self.extended else 0x00]))
            if self.target:
                mac = bytes(int(x, 16) for x in self.target.split(":"))[::-1]
                t.send(CMD_MAC_FILTER, mac)
                t.send(CMD_ADV_HOP)
            else:
                t.send(CMD_MAC_FILTER)
            t.send(CMD_CRC_VALID, bytes([0x01]))
            t.send(CMD_PHY_PRELOAD, bytes([PHY_2M]))
            t.send(CMD_VERSION)

    # -- following ---------------------------------------------------------

    async def follow(self, address: str, address_type: str | None = None) -> bool:
        # Sniffle filters connection-follow on the 6 MAC bytes alone, so the
        # address type is accepted for interface parity but not needed here.
        del address_type
        if self._transport is None:
            return False
        try:
            mac = bytes(int(x, 16) for x in address.upper().split(":"))[::-1]
        except ValueError:
            return False
        if len(mac) != 6:
            return False
        with self._command_lock:
            self._transport.send(CMD_MAC_FILTER, mac)
            self._transport.send(CMD_ADV_HOP)
            self._transport.send(CMD_FOLLOW, bytes([0x01]))
        self.target = address.upper()
        self._followed = self.target
        self.emit(
            BackendStatus(
                "following",
                f"Aimed at {address}. Hopping 37/38/39 to catch its connection setup; "
                "once it connects we will follow onto the data channels.",
                {"target": address},
            )
        )
        return True

    async def unfollow(self) -> None:
        if self._transport is None:
            return
        with self._command_lock:
            self._transport.send(CMD_MAC_FILTER)
            self._transport.send(
                CMD_CHAN_AA_PHY,
                struct.pack("<BLBL", self.channel, BLE_ADV_ACCESS_ADDRESS, PHY_1M, BLE_ADV_CRC_INIT),
            )
        self.target = None
        self._followed = None
        self.emit(
            BackendStatus(
                "scanning",
                f"Spotlight released — back to broad advertising capture on channel "
                f"{self.channel}.",
            )
        )

    # -- reader ------------------------------------------------------------

    def _reader(self) -> None:
        transport = self._transport
        loop = self._loop
        assert loop is not None
        errors = 0
        while self.running and transport is not None:
            try:
                message = transport.recv()
            except Exception:
                errors += 1
                if errors > 20:
                    self.emit_threadsafe(
                        loop, BackendStatus("error", "Lost contact with the sniffer.")
                    )
                    return
                continue
            if message is None:
                continue
            errors = 0
            msg_type, body = message
            try:
                self._dispatch(loop, msg_type, body)
            except Exception:
                transport.resync()

    def _dispatch(self, loop: asyncio.AbstractEventLoop, msg_type: int, body: bytes) -> None:
        if msg_type == MSG_PACKET:
            self._handle_packet(loop, body)
        elif msg_type == MSG_STATE and body:
            state = SNIFFER_STATES.get(body[0], f"state {body[0]}")
            self._in_connection = body[0] == 3
            self.emit_threadsafe(
                loop,
                BackendStatus(
                    "following" if self._in_connection else "scanning",
                    f"Sniffer is {state}."
                    + (
                        " Advertising capture is paused while it stays on this connection."
                        if self._in_connection
                        else ""
                    ),
                    {"sniffer_state": state, "target": self._followed},
                ),
            )
        elif msg_type == MSG_MEASUREMENT and body:
            if body[0] == 0x00 and len(body) > 1:  # version measurement
                self._firmware = body[1:].decode("utf-8", errors="replace").strip("\x00")
        elif msg_type == MSG_DEBUG:
            text = body.decode("utf-8", errors="replace").strip()
            if text:
                self.emit_threadsafe(loop, BackendStatus("debug", text))

    def _handle_packet(self, loop: asyncio.AbstractEventLoop, body: bytes) -> None:
        if len(body) < 10:
            return
        _ts, length, _event, rssi, chan_byte = struct.unpack("<LHHbB", body[:10])
        pdu = body[10:]

        crc_error = bool(length & 0x4000)
        direction = "peripheral" if (length >> 15) else "central"
        phy = PHY_NAMES.get(chan_byte >> 6, "1M")
        channel = chan_byte & 0x3F
        self._current_channel = channel
        self._current_phy = phy
        now = time.time()

        if crc_error:
            return  # a corrupt packet tells us nothing we can trust

        if channel >= 37:
            self._emit_advertising(loop, pdu, rssi, channel, phy, now)
        else:
            event = decode_data_pdu(pdu, now, direction, encrypted=False)
            event.address = self._followed
            event.detail.setdefault("channel", channel)
            event.detail.setdefault("phy", phy)
            event.detail.setdefault("rssi", rssi)
            self.emit_threadsafe(loop, event)

    def _emit_advertising(
        self,
        loop: asyncio.AbstractEventLoop,
        pdu: bytes,
        rssi: int,
        channel: int,
        phy: str,
        now: float,
    ) -> None:
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
                    summary=(
                        f"{parsed.target_address} is opening a connection to {parsed.address}"
                    ),
                    detail={
                        "initiator": parsed.target_address,
                        "advertiser": parsed.address,
                        "channel": channel,
                    },
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
                source="sniffle",
            ),
        )



register("sniffle", SniffleBackend, priority=10)
