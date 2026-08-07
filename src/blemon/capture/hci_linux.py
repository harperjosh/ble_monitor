"""Linux capture by decoding the raw HCI socket.

This is the best host-adapter backend and it is the reason the Raspberry Pi is
the recommended place to run this. It reads LE Advertising Report and LE
Extended Advertising Report events straight off the controller, which gives
real MAC addresses, address types, complete unmodified payloads and BT5
extended advertising.

We deliberately do **not** use BlueZ's D-Bus API. D-Bus hands you a cooked
summary — it drops the raw advertising payload, hides address types and
de-duplicates packets — and every one of those is something this tool needs.

Two modes:

``user`` (default)
    Take exclusive control of the adapter over ``HCI_CHANNEL_USER`` and drive
    the scan ourselves. Requires the adapter to be down, which we will do for
    you over the management socket and undo on exit.

``monitor``
    Read-only. Attaches to ``HCI_CHANNEL_MONITOR``, the same feed ``btmon``
    uses, and decodes whatever advertising reports the controller is already
    producing for somebody else. Useful when you cannot take the adapter, but
    you only see traffic while something else is scanning.
"""

from __future__ import annotations

import asyncio
import errno
import os
import socket
import struct
import threading
import time
from collections.abc import AsyncIterator

from blemon.capture.base import BackendStatus, CaptureError, Event, QueueBackend, register
from blemon.models import Advertisement, Capabilities, PduType, classify_address

AF_BLUETOOTH = 31
BTPROTO_HCI = 1
HCI_CHANNEL_RAW = 0
HCI_CHANNEL_USER = 1
HCI_CHANNEL_MONITOR = 2
HCI_CHANNEL_CONTROL = 3
HCI_DEV_NONE = 0xFFFF

HCI_COMMAND_PKT = 0x01
HCI_EVENT_PKT = 0x04

EVT_COMMAND_COMPLETE = 0x0E
EVT_COMMAND_STATUS = 0x0F
EVT_LE_META = 0x3E

SUBEVT_ADV_REPORT = 0x02
SUBEVT_EXT_ADV_REPORT = 0x0D

OCF_RESET = 0x0C03
OCF_SET_EVENT_MASK = 0x0C01
OCF_LE_SET_EVENT_MASK = 0x2001
OCF_LE_READ_LOCAL_FEATURES = 0x2003
OCF_LE_SET_SCAN_PARAMS = 0x200B
OCF_LE_SET_SCAN_ENABLE = 0x200C
OCF_LE_SET_EXT_SCAN_PARAMS = 0x2041
OCF_LE_SET_EXT_SCAN_ENABLE = 0x2042

MGMT_OP_SET_POWERED = 0x0005
MGMT_EV_CMD_COMPLETE = 0x0001
MGMT_EV_CMD_STATUS = 0x0002

#: LE feature bit 12 — LE Extended Advertising.
LE_FEATURE_EXTENDED_ADVERTISING = 12

PHY_NAMES = {0x01: "1M", 0x02: "2M", 0x03: "Coded"}

LEGACY_PDU_TYPES = {
    0x00: PduType.ADV_IND,
    0x01: PduType.ADV_DIRECT_IND,
    0x02: PduType.ADV_SCAN_IND,
    0x03: PduType.ADV_NONCONN_IND,
    0x04: PduType.SCAN_RSP,
}


def _hci_devices() -> list[int]:
    """Adapter indices present on this machine, from sysfs."""
    base = "/sys/class/bluetooth"
    if not os.path.isdir(base):
        return []
    out = []
    for name in sorted(os.listdir(base)):
        if name.startswith("hci") and name[3:].isdigit():
            out.append(int(name[3:]))
    return out


def _adapter_is_up(index: int) -> bool | None:
    """True/False from sysfs, or None when we cannot tell."""
    for candidate in (
        f"/sys/class/bluetooth/hci{index}/rfkill{index}/soft",
        f"/sys/class/bluetooth/hci{index}/power/runtime_status",
    ):
        try:
            with open(candidate) as fh:
                value = fh.read().strip()
            if candidate.endswith("soft"):
                return value == "0"
            return value == "active"
        except OSError:
            continue
    return None


class ManagementSocket:
    """Minimal BlueZ management-socket client, used only to power an adapter."""

    def __init__(self) -> None:
        self.sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
        self.sock.settimeout(3.0)
        self.sock.bind((HCI_DEV_NONE, HCI_CHANNEL_CONTROL))

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def set_powered(self, index: int, powered: bool) -> bool:
        payload = struct.pack("<HHH", MGMT_OP_SET_POWERED, index, 1) + bytes([1 if powered else 0])
        self.sock.send(payload)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                data = self.sock.recv(1024)
            except TimeoutError:
                return False
            except OSError:
                return False
            if len(data) < 6:
                continue
            evt, _idx, plen = struct.unpack("<HHH", data[:6])
            body = data[6 : 6 + plen]
            if evt == MGMT_EV_CMD_COMPLETE and len(body) >= 3:
                opcode, status = struct.unpack("<HB", body[:3])
                if opcode == MGMT_OP_SET_POWERED:
                    return status == 0
            elif evt == MGMT_EV_CMD_STATUS and len(body) >= 3:
                opcode, status = struct.unpack("<HB", body[:3])
                if opcode == MGMT_OP_SET_POWERED:
                    return status == 0
        return False


class HciBackend(QueueBackend):
    """Raw HCI socket capture on Linux."""

    name = "hci"

    def __init__(
        self,
        device: int = 0,
        mode: str = "user",
        scan_interval_ms: float = 60.0,
        scan_window_ms: float = 60.0,
        extended: bool = True,
        restore_adapter: bool = True,
        **_: object,
    ) -> None:
        super().__init__()
        self.device = int(device)
        self.mode = mode
        self.scan_interval = max(2.5, scan_interval_ms)
        self.scan_window = max(2.5, min(scan_window_ms, scan_interval_ms))
        self.want_extended = extended
        self.restore_adapter = restore_adapter

        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._powered_off_by_us = False
        self._extended_active = False
        self._monitor_mode = mode == "monitor"
        self._parse_errors = 0

    # -- capability declaration -------------------------------------------

    @property
    def capabilities(self) -> Capabilities:
        caveats = [
            "A host Bluetooth adapter can only receive advertising packets on channels "
            "37, 38 and 39. It cannot see what devices say to each other once they are "
            "connected — that needs a sniffer.",
            "The controller does not report which of the three advertising channels a "
            "packet arrived on, so per-packet channel numbers are unavailable here.",
        ]
        if self._monitor_mode:
            caveats.append(
                "Running in read-only monitor mode: you will only see advertisements "
                "while something else on this machine is scanning."
            )
        return Capabilities(
            name=f"Linux HCI (hci{self.device}, {'monitor' if self._monitor_mode else 'exclusive'})",
            description="Raw HCI socket, decoding LE Advertising Report events directly.",
            advertising=True,
            extended_advertising=self._extended_active,
            real_mac_addresses=True,
            raw_payloads=True,
            scan_responses=True,
            connection_following=False,
            three_channel_advertising=False,
            coded_phy=self._extended_active,
            two_m_phy=self._extended_active,
            can_transmit=False,
            channel_reporting=False,
            caveats=caveats,
        )

    @staticmethod
    def available() -> tuple[bool, str]:
        if not hasattr(socket, "AF_BLUETOOTH"):
            return False, "this Python build has no AF_BLUETOOTH support"
        if os.uname().sysname != "Linux":
            return False, "raw HCI capture is Linux-only"
        if not _hci_devices():
            return False, "no Bluetooth adapter found under /sys/class/bluetooth"
        return True, ""

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        devices = _hci_devices()
        if not devices:
            raise CaptureError(
                "No Bluetooth adapter found.",
                remedy="Check `hciconfig -a` or `rfkill list`. On a Pi, confirm the "
                "adapter is not blocked with `rfkill unblock bluetooth`.",
            )
        if self.device not in devices:
            raise CaptureError(
                f"hci{self.device} does not exist. Present adapters: "
                + ", ".join(f"hci{d}" for d in devices),
                remedy=f"Try `blemon scan --device {devices[0]}`.",
            )

        if self._monitor_mode:
            self._sock = self._open_monitor()
        else:
            self._sock = self._open_exclusive()
            self._configure_scan(self._sock)

        await super().start()
        self._status = BackendStatus(
            "scanning",
            (
                f"Reading advertising reports from hci{self.device}"
                + (" (read-only monitor)" if self._monitor_mode else "")
                + ("; extended advertising enabled" if self._extended_active else "")
            ),
            {"device": self.device, "extended": self._extended_active},
        )
        self._thread = threading.Thread(target=self._reader, name="blemon-hci", daemon=True)
        self._thread.start()

    async def stop(self) -> None:
        await super().stop()
        sock = self._sock
        self._sock = None
        if sock is not None:
            if not self._monitor_mode:
                try:
                    self._send_command(sock, OCF_LE_SET_SCAN_ENABLE, bytes([0x00, 0x00]), wait=False)
                except OSError:
                    pass
            try:
                sock.close()
            except OSError:
                pass
        if self._powered_off_by_us and self.restore_adapter:
            try:
                mgmt = ManagementSocket()
                mgmt.set_powered(self.device, True)
                mgmt.close()
            except OSError:
                pass
            self._powered_off_by_us = False

    # -- socket setup ------------------------------------------------------

    def _bind(self, channel: int) -> socket.socket:
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
        sock.settimeout(1.0)
        index = HCI_DEV_NONE if channel == HCI_CHANNEL_MONITOR else self.device
        sock.bind((index, channel))
        return sock

    def _open_monitor(self) -> socket.socket:
        try:
            return self._bind(HCI_CHANNEL_MONITOR)
        except PermissionError as exc:
            raise self._permission_error(exc) from exc
        except OSError as exc:
            raise CaptureError(
                f"Could not open the HCI monitor channel: {exc}",
                remedy="Monitor mode needs CAP_NET_RAW. See `blemon doctor`.",
            ) from exc

    def _open_exclusive(self) -> socket.socket:
        try:
            return self._bind(HCI_CHANNEL_USER)
        except PermissionError as exc:
            raise self._permission_error(exc) from exc
        except OSError as exc:
            if exc.errno not in (errno.EBUSY, errno.EINVAL):
                raise CaptureError(
                    f"Could not take exclusive control of hci{self.device}: {exc}",
                    remedy="Try read-only monitor mode: `blemon scan --hci-mode monitor`.",
                ) from exc

        # EBUSY means BlueZ has the adapter. Take it down and try once more.
        powered_off = False
        try:
            mgmt = ManagementSocket()
            powered_off = mgmt.set_powered(self.device, False)
            mgmt.close()
        except PermissionError as exc:
            raise self._permission_error(exc) from exc
        except OSError:
            powered_off = False

        if powered_off:
            self._powered_off_by_us = True
            time.sleep(0.25)
            try:
                return self._bind(HCI_CHANNEL_USER)
            except OSError:
                pass

        raise CaptureError(
            f"hci{self.device} is in use by BlueZ and could not be released.",
            remedy=(
                f"Either stop BlueZ using it (`sudo hciconfig hci{self.device} down`, or "
                "`sudo systemctl stop bluetooth`) and try again, or run read-only with "
                "`blemon scan --hci-mode monitor`. Run `blemon doctor` for the full picture."
            ),
        )

    def _permission_error(self, exc: OSError) -> CaptureError:
        return CaptureError(
            f"Permission denied opening the Bluetooth socket on hci{self.device}: {exc}",
            remedy=(
                "Grant the capabilities rather than running everything as root:\n"
                f"  sudo setcap 'cap_net_raw,cap_net_admin+eip' $(readlink -f {os.sys.executable})\n"
                "…or run this one command with sudo. `blemon doctor` will confirm once it works."
            ),
        )

    # -- HCI command plumbing ---------------------------------------------

    def _send_command(
        self, sock: socket.socket, opcode: int, params: bytes = b"", wait: bool = True
    ) -> bytes:
        packet = bytes([HCI_COMMAND_PKT]) + struct.pack("<HB", opcode, len(params)) + params
        sock.send(packet)
        if not wait:
            return b""
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                data = sock.recv(1024)
            except TimeoutError:
                continue
            if len(data) < 4 or data[0] != HCI_EVENT_PKT:
                continue
            code, plen = data[1], data[2]
            body = data[3 : 3 + plen]
            if code == EVT_COMMAND_COMPLETE and len(body) >= 3:
                _ncmd, got = struct.unpack("<BH", body[:3])
                if got == opcode:
                    return body[3:]
            elif code == EVT_COMMAND_STATUS and len(body) >= 4:
                status, _ncmd, got = struct.unpack("<BBH", body[:4])
                if got == opcode:
                    if status != 0:
                        raise CaptureError(
                            f"HCI command 0x{opcode:04X} failed with status 0x{status:02X}.",
                            remedy="Run `blemon doctor` to check the adapter's state.",
                        )
                    return b""
        raise CaptureError(
            f"The controller did not answer HCI command 0x{opcode:04X}.",
            remedy="The adapter may be wedged. Try `sudo hciconfig hci"
            f"{self.device} reset`, or unplug and replug a USB dongle.",
        )

    def _configure_scan(self, sock: socket.socket) -> None:
        self._send_command(sock, OCF_RESET)
        # Enable all standard events, and every LE meta event in the low word,
        # which covers both the legacy and extended advertising reports.
        self._send_command(sock, OCF_SET_EVENT_MASK, b"\xff\xff\xfb\xff\x07\xf8\xbf\x3d")
        self._send_command(sock, OCF_LE_SET_EVENT_MASK, b"\xff\xff\x00\x00\x00\x00\x00\x00")

        supports_extended = False
        if self.want_extended:
            try:
                features = self._send_command(sock, OCF_LE_READ_LOCAL_FEATURES)
                if len(features) >= 9:
                    mask = int.from_bytes(features[1:9], "little")
                    supports_extended = bool(mask >> LE_FEATURE_EXTENDED_ADVERTISING & 1)
            except CaptureError:
                supports_extended = False

        interval = int(self.scan_interval / 0.625)
        window = int(self.scan_window / 0.625)

        if supports_extended:
            try:
                # own_addr_type=random-free public, filter policy accept-all,
                # scanning_phys = 1M | Coded so long-range devices show up too.
                params = struct.pack("<BBB", 0x00, 0x00, 0x05)
                params += struct.pack("<BHH", 0x00, interval, window)  # 1M, passive
                params += struct.pack("<BHH", 0x00, interval, window)  # Coded, passive
                self._send_command(sock, OCF_LE_SET_EXT_SCAN_PARAMS, params)
                # filter_duplicates=0: we need every packet, since advertising
                # rate and rotation correlation both depend on the real count.
                self._send_command(
                    sock, OCF_LE_SET_EXT_SCAN_ENABLE, struct.pack("<BBHH", 0x01, 0x00, 0, 0)
                )
                self._extended_active = True
                return
            except CaptureError:
                self._extended_active = False

        self._send_command(
            sock,
            OCF_LE_SET_SCAN_PARAMS,
            struct.pack("<BHHBB", 0x00, interval, window, 0x00, 0x00),
        )
        self._send_command(sock, OCF_LE_SET_SCAN_ENABLE, bytes([0x01, 0x00]))

    # -- reader thread -----------------------------------------------------

    def _reader(self) -> None:
        sock = self._sock
        loop = self._loop
        assert loop is not None
        while self.running and sock is not None:
            try:
                data = sock.recv(2048)
            except TimeoutError:
                continue
            except OSError:
                if self.running:
                    self.emit_threadsafe(
                        loop,
                        BackendStatus("error", "The HCI socket closed unexpectedly."),
                    )
                return
            if not data:
                continue
            try:
                if self._monitor_mode:
                    self._handle_monitor(loop, data)
                else:
                    self._handle_hci(loop, data)
            except Exception:
                self._parse_errors += 1

    def _handle_monitor(self, loop: asyncio.AbstractEventLoop, data: bytes) -> None:
        if len(data) < 6:
            return
        opcode, index, plen = struct.unpack("<HHH", data[:6])
        # 0x0003 is HCI_MON_EVENT_PKT — a controller-to-host HCI event.
        if opcode != 0x0003 or index != self.device:
            return
        self._handle_hci(loop, bytes([HCI_EVENT_PKT]) + data[6 : 6 + plen])

    def _handle_hci(self, loop: asyncio.AbstractEventLoop, data: bytes) -> None:
        if len(data) < 3 or data[0] != HCI_EVENT_PKT:
            return
        code, plen = data[1], data[2]
        if code != EVT_LE_META:
            return
        body = data[3 : 3 + plen]
        if not body:
            return
        subevent = body[0]
        if subevent == SUBEVT_ADV_REPORT:
            for adv in self._parse_legacy_reports(body):
                self.emit_threadsafe(loop, adv)
        elif subevent == SUBEVT_EXT_ADV_REPORT:
            for adv in self._parse_extended_reports(body):
                self.emit_threadsafe(loop, adv)

    def _parse_legacy_reports(self, body: bytes) -> list[Advertisement]:
        out: list[Advertisement] = []
        if len(body) < 2:
            return out
        count = body[1]
        offset = 2
        now = time.time()
        for _ in range(count):
            if offset + 9 > len(body):
                break
            event_type = body[offset]
            addr_type = body[offset + 1]
            addr = ":".join(f"{b:02X}" for b in body[offset + 2 : offset + 8][::-1])
            data_len = body[offset + 8]
            offset += 9
            payload = body[offset : offset + data_len]
            offset += data_len
            if offset >= len(body):
                break
            rssi = struct.unpack("<b", body[offset : offset + 1])[0]
            offset += 1
            pdu = LEGACY_PDU_TYPES.get(event_type, PduType.UNKNOWN)
            out.append(
                Advertisement(
                    address=addr,
                    timestamp=now,
                    rssi=None if rssi == 127 else rssi,
                    address_type=classify_address(addr, addr_type in (1, 3)),
                    raw=bytes(payload),
                    channel=None,  # the controller does not tell us
                    pdu_type=pdu,
                    phy="1M",
                    scan_response=pdu is PduType.SCAN_RSP,
                    connectable=event_type in (0x00, 0x01),
                    source=f"hci{self.device}",
                )
            )
        return out

    def _parse_extended_reports(self, body: bytes) -> list[Advertisement]:
        out: list[Advertisement] = []
        if len(body) < 2:
            return out
        count = body[1]
        offset = 2
        now = time.time()
        for _ in range(count):
            if offset + 24 > len(body):
                break
            event_type = struct.unpack("<H", body[offset : offset + 2])[0]
            addr_type = body[offset + 2]
            addr = ":".join(f"{b:02X}" for b in body[offset + 3 : offset + 9][::-1])
            primary_phy = body[offset + 9]
            secondary_phy = body[offset + 10]
            tx_power = struct.unpack("<b", body[offset + 12 : offset + 13])[0]
            rssi = struct.unpack("<b", body[offset + 13 : offset + 14])[0]
            data_len = body[offset + 23]
            offset += 24
            payload = body[offset : offset + data_len]
            offset += data_len

            legacy = bool(event_type & 0x0010)
            scan_rsp = bool(event_type & 0x0008)
            connectable = bool(event_type & 0x0001)
            if legacy:
                pdu = PduType.SCAN_RSP if scan_rsp else PduType.ADV_IND
            else:
                pdu = PduType.ADV_EXT_IND
            phy = PHY_NAMES.get(secondary_phy) or PHY_NAMES.get(primary_phy, "1M")

            out.append(
                Advertisement(
                    address=addr,
                    timestamp=now,
                    rssi=None if rssi == 127 else rssi,
                    address_type=classify_address(addr, addr_type in (1, 3)),
                    raw=bytes(payload),
                    channel=None,
                    pdu_type=pdu,
                    phy=phy,
                    scan_response=scan_rsp,
                    connectable=connectable,
                    tx_power_adv=None if tx_power == 127 else tx_power,
                    source=f"hci{self.device}",
                )
            )
        return out

    async def stream(self) -> AsyncIterator[Event]:
        yield self._status
        async for event in super().stream():
            yield event


register("hci", HciBackend, priority=30)
