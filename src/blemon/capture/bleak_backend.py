"""CoreBluetooth capture via bleak — the macOS backend.

Read this before trusting anything it produces:

**macOS does not give applications the MAC address of a device.** CoreBluetooth
substitutes a UUID that is generated per application, per device, and is not
stable across reinstalls. That single fact degrades a great deal:

* You cannot tell a device using a permanent public address from one carefully
  rotating a private address every fifteen minutes — the OS hides both behind
  the same opaque handle. All address-privacy analysis is unavailable.
* Continuity across MAC rotation is meaningless, because you never see the MAC.
* Two captures on two Macs cannot be compared, and neither can two captures on
  the same Mac after a reinstall.

**CoreBluetooth also does not hand over the raw advertising payload.** It gives
a parsed summary. We reconstruct a byte payload from that summary so the decode
layer has something to work with, and it decodes correctly — but it is a
reconstruction, not a capture, and the byte offsets are ours rather than the
advertiser's. The capability declaration says so and the UI shows it.

None of this is bleak's fault; it is the platform. If you want the real
picture, run the capture service on a Raspberry Pi and point the dashboard at
it over your LAN. The Mac makes a perfectly good screen for a Pi's radio.
"""

from __future__ import annotations

import asyncio
import platform
import struct
import time
from typing import Any

from blemon.capture.base import BackendStatus, CaptureError, QueueBackend, register
from blemon.models import AddressType, Advertisement, Capabilities, PduType, classify_address


def _reconstruct_payload(
    local_name: str | None,
    manufacturer_data: dict[int, bytes],
    service_data: dict[str, bytes],
    service_uuids: list[str],
    tx_power: int | None,
) -> bytes:
    """Rebuild an AD payload from CoreBluetooth's parsed summary.

    Field *values* are exactly what the OS reported. Field *order and framing*
    are ours, because the original was discarded before we saw it.
    """
    out = bytearray()

    def add(type_code: int, value: bytes) -> None:
        if not value or len(value) > 254:
            return
        out.append(len(value) + 1)
        out.append(type_code)
        out.extend(value)

    uuid16 = bytearray()
    uuid128 = bytearray()
    for uuid in service_uuids or []:
        cleaned = uuid.replace("-", "").upper()
        if len(cleaned) == 32 and cleaned.endswith("00001000800000805F9B34FB"):
            uuid16 += bytes.fromhex(cleaned[4:8])[::-1]
        elif len(cleaned) == 32:
            uuid128 += bytes.fromhex(cleaned)[::-1]
        elif len(cleaned) == 4:
            uuid16 += bytes.fromhex(cleaned)[::-1]
    if uuid16:
        add(0x03, bytes(uuid16))
    if uuid128:
        add(0x07, bytes(uuid128))

    if local_name:
        add(0x09, local_name.encode("utf-8"))
    if tx_power is not None:
        add(0x0A, struct.pack("<b", max(-127, min(127, int(tx_power)))))

    for uuid, body in (service_data or {}).items():
        cleaned = uuid.replace("-", "").upper()
        if len(cleaned) == 32 and cleaned.endswith("00001000800000805F9B34FB"):
            add(0x16, bytes.fromhex(cleaned[4:8])[::-1] + bytes(body))
        elif len(cleaned) == 32:
            add(0x21, bytes.fromhex(cleaned)[::-1] + bytes(body))
        elif len(cleaned) == 4:
            add(0x16, bytes.fromhex(cleaned)[::-1] + bytes(body))

    for company_id, body in (manufacturer_data or {}).items():
        add(0xFF, struct.pack("<H", int(company_id)) + bytes(body))

    return bytes(out)


class BleakBackend(QueueBackend):
    """Cross-platform host-adapter capture through bleak/CoreBluetooth."""

    name = "bleak"

    def __init__(self, adapter: str | None = None, **_: object) -> None:
        super().__init__()
        self.adapter = adapter
        self._scanner = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._is_macos = platform.system() == "Darwin"
        #: Resolved in start(). We try passive first so the default posture is
        #: genuinely receive-only; only if the platform refuses do we fall back
        #: to active scanning, and then we disclose it in the caveats.
        self._scan_mode = "passive"

    @property
    def capabilities(self) -> Capabilities:
        caveats = [
            "A host Bluetooth adapter only receives advertising packets. It cannot see "
            "what devices say once they are connected — that needs a sniffer.",
            "The advertising payload shown here is reconstructed from the operating "
            "system's parsed summary. The values are real; the byte layout is ours.",
        ]
        if self._is_macos:
            caveats.insert(
                0,
                "macOS hides MAC addresses. Every device is identified by a UUID that "
                "this application alone sees, so address privacy cannot be assessed, "
                "rotation cannot be correlated, and captures cannot be compared across "
                "machines. Run the capture service on a Raspberry Pi for the real picture.",
            )
        else:
            caveats.insert(
                0,
                "On Linux this path goes through BlueZ over D-Bus, which discards raw "
                "advertising data and de-duplicates packets. The `hci` backend is "
                "strictly better here — use it unless it cannot start.",
            )
        if self._scan_mode == "active":
            caveats.append(
                "This platform did not permit passive scanning, so active scanning is in "
                "use — it transmits scan requests. If strictly receive-only capture matters "
                "to you, use the `hci` backend on Linux or a sniffer.",
            )
        return Capabilities(
            name=f"CoreBluetooth via bleak ({platform.system()})",
            description="Host adapter scanning through the operating system's own stack.",
            advertising=True,
            extended_advertising=False,
            real_mac_addresses=not self._is_macos,
            raw_payloads=False,
            scan_responses=True,
            connection_following=False,
            three_channel_advertising=False,
            coded_phy=False,
            two_m_phy=False,
            # Active scanning transmits SCAN_REQ packets. Reporting False while
            # the radio is doing that tells a user who picked this tool for
            # receive-only capture the opposite of what is happening.
            can_transmit=self._scan_mode == "active",
            channel_reporting=False,
            caveats=caveats,
        )

    @staticmethod
    def available() -> tuple[bool, str]:
        try:
            import bleak  # noqa: F401
        except ImportError:
            return False, "bleak is not installed (pip install bleak)"
        system = platform.system()
        if system == "Darwin":
            return True, ""
        if system == "Linux":
            # bleak imports fine on any Linux box, including one with no radio.
            # Claiming availability there would make autoselect pick a backend
            # that is guaranteed to fail at start.
            import os

            if not os.path.isdir("/sys/class/bluetooth") or not os.listdir("/sys/class/bluetooth"):
                return False, "no Bluetooth adapter found under /sys/class/bluetooth"
            return True, ""
        return False, f"{system} is not a supported platform for this backend"

    async def start(self) -> None:
        try:
            from bleak import BleakScanner
        except ImportError as exc:
            raise CaptureError(
                "bleak is not installed, so the host adapter cannot be used.",
                remedy="pip install bleak",
            ) from exc

        self._loop = asyncio.get_running_loop()
        base_kwargs: dict[str, object] = {}
        if self.adapter:
            base_kwargs["adapter"] = self.adapter

        # Receive-only is the default posture, so try passive scanning first —
        # passive never transmits a scan request. Passive is not available on
        # every platform/adapter (BlueZ needs a filter), so fall back to active
        # if it will not start, and disclose that fallback in the capabilities.
        last_exc: Exception | None = None
        for mode in ("passive", "active"):
            try:
                self._scanner = BleakScanner(
                    detection_callback=self._on_detection, scanning_mode=mode, **base_kwargs
                )
                await self._scanner.start()
                self._scan_mode = mode
                last_exc = None
                break
            except Exception as exc:  # noqa: BLE001 — try the next mode
                last_exc = exc
                self._scanner = None
        if last_exc is not None:
            raise CaptureError(
                f"Could not start scanning: {last_exc}",
                remedy=(
                    "On macOS, grant Bluetooth permission to your terminal in System "
                    "Settings › Privacy & Security › Bluetooth, then try again. "
                    "Run `blemon doctor` to confirm."
                    if self._is_macos
                    else "Check that the adapter is up and that bluetoothd is running."
                ),
            ) from last_exc

        await super().start()
        self._status = BackendStatus(
            "scanning",
            "Scanning through the operating system's Bluetooth stack."
            + (
                " macOS is hiding MAC addresses — device identity is degraded."
                if self._is_macos
                else ""
            ),
        )

    async def stop(self) -> None:
        await super().stop()
        if self._scanner is not None:
            try:
                await self._scanner.stop()
            except Exception:
                pass
            self._scanner = None

    def _on_detection(self, device, advertisement_data) -> None:
        raw = _reconstruct_payload(
            getattr(advertisement_data, "local_name", None),
            dict(getattr(advertisement_data, "manufacturer_data", {}) or {}),
            dict(getattr(advertisement_data, "service_data", {}) or {}),
            list(getattr(advertisement_data, "service_uuids", []) or []),
            getattr(advertisement_data, "tx_power", None),
        )
        address = str(getattr(device, "address", "") or "")
        address_type = _resolve_address_type(device, address, self._is_macos)

        self.emit(
            Advertisement(
                address=address,
                timestamp=time.time(),
                rssi=getattr(advertisement_data, "rssi", None),
                address_type=address_type,
                raw=raw,
                channel=None,
                pdu_type=PduType.ADV_IND,
                phy="1M",
                scan_response=False,
                connectable=getattr(advertisement_data, "connectable", None),
                source="bleak",
            )
        )



def _resolve_address_type(device: object, address: str, is_macos: bool) -> AddressType:
    """Best available address type from what the OS actually tells us.

    macOS never reveals the real address, so it is always OPAQUE. On BlueZ the
    device details carry the true "AddressType" ("public"/"random"), and when
    they do we use it — a public address must not be run through the random-bit
    classifier, which would read a normal OUI's top bits as a private address
    and invert the entire privacy verdict. When the type is genuinely unknown we
    return UNKNOWN rather than guessing, so an unknowable device is not fed into
    rotation-correlation or scored as if it were deliberately private.

    ``details`` is platform-shaped: BlueZ gives a dict with a "props" mapping,
    WinRT gives a raw advertisement object and Android a platform object. Read
    the declaration wherever it lives rather than only from the BlueZ shape —
    matching just that one silently returns UNKNOWN for every device on every
    other platform, which quietly disables address-type privacy scoring instead
    of failing visibly.
    """
    if is_macos:
        return AddressType.OPAQUE
    declared = _declared_address_type(getattr(device, "details", None))
    if declared == "public":
        return AddressType.PUBLIC
    if declared == "random":
        return classify_address(address, random=True)
    return AddressType.UNKNOWN


def _declared_address_type(details: object) -> str:
    """The OS's own word for the address type, from any backend's details shape."""
    if details is None:
        return ""
    props: Any = details
    if isinstance(details, dict):
        props = details.get("props", details)
    if isinstance(props, dict):
        for key in ("AddressType", "address_type", "BluetoothAddressType"):
            if key in props:
                return str(props[key]).lower()
        return ""
    # WinRT / Android expose it as an attribute on a platform object, and WinRT
    # spells the value "Public"/"Random"/"Unspecified".
    for key in ("address_type", "AddressType", "BluetoothAddressType"):
        value = getattr(props, key, None)
        if value is not None:
            return str(getattr(value, "name", value)).lower()
    return ""


register("bleak", BleakBackend, priority=40)
