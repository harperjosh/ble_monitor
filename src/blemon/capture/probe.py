"""Active GATT probing — opt-in only, never automatic.

Everything else in this tool is receive-only. This module is the one exception,
and it is deliberately awkward to invoke by accident:

* It is never called by the capture loop, the hub, or any background task.
* Every call needs an explicit action — a CLI command or a per-device button.
* Connecting is **visible to the target device**. It appears in its logs, it
  may prompt its user, and it briefly interrupts whatever else it was doing.
  The warning is returned in the result, not buried in documentation.
* Allowlist mode restricts probing to hardware you have marked as your own,
  and is the recommended way to run.
* There is no bulk mode. Probing takes one address.

What you get for it is a large jump in identification quality: exact model,
manufacturer, firmware revision, battery level, and the real service list
rather than whatever the device chose to advertise.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from blemon.decode.assigned import characteristic_name, normalize_uuid, service_name
from blemon.models import Confidence, Evidence, Guess

PROBE_WARNING = (
    "Connecting is an active transmission. The target device will see it, may log it, "
    "and may briefly stop whatever it was doing. This is the one part of ble-monitor "
    "that is not passive."
)

#: Characteristics worth reading during a probe, and what they tell you.
READABLE_CHARACTERISTICS: dict[str, str] = {
    "2A00": "Device Name",
    "2A01": "Appearance",
    "2A19": "Battery Level",
    "2A23": "System ID",
    "2A24": "Model Number",
    "2A25": "Serial Number",
    "2A26": "Firmware Revision",
    "2A27": "Hardware Revision",
    "2A28": "Software Revision",
    "2A29": "Manufacturer Name",
    "2A50": "PnP ID",
}

#: Never read these even though they are technically readable — they are
#: either personal data or large enough to be rude.
SKIP_CHARACTERISTICS = {"2A9C", "2A9D", "2A9E", "2A5B", "2A18", "2A34"}


@dataclass
class ProbeResult:
    address: str
    success: bool
    started_at: float
    duration: float = 0.0
    error: str | None = None
    remedy: str | None = None
    services: list[dict[str, Any]] = field(default_factory=list)
    device_info: dict[str, str] = field(default_factory=dict)
    warning: str = PROBE_WARNING

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "success": self.success,
            "started_at": self.started_at,
            "duration": round(self.duration, 3),
            "error": self.error,
            "remedy": self.remedy,
            "services": self.services,
            "device_info": self.device_info,
            "warning": self.warning,
            "summary": self.summary(),
        }

    def summary(self) -> str:
        if not self.success:
            return f"Probe of {self.address} failed: {self.error}"
        info = self.device_info
        bits = []
        if info.get("Manufacturer Name"):
            bits.append(info["Manufacturer Name"])
        if info.get("Model Number"):
            bits.append(info["Model Number"])
        if info.get("Firmware Revision"):
            bits.append(f"firmware {info['Firmware Revision']}")
        if info.get("Battery Level"):
            bits.append(f"battery {info['Battery Level']}")
        head = ", ".join(bits) if bits else "no device-information service"
        return (
            f"{self.address}: {head}. "
            f"{len(self.services)} services, "
            f"{sum(len(s.get('characteristics', [])) for s in self.services)} characteristics."
        )

    def to_guesses(self) -> list[Guess]:
        """Turn probe findings into identification guesses.

        A probe is a direct read rather than an inference, so these carry the
        highest confidence in the system — but they are still returned through
        the same guess/evidence machinery so the UI treats them uniformly.
        """
        out: list[Guess] = []
        info = self.device_info
        model = info.get("Model Number")
        vendor = info.get("Manufacturer Name")
        if model:
            label = f"{vendor} {model}".strip() if vendor else model
            out.append(
                Guess(
                    label=label,
                    confidence=Confidence.CERTAIN,
                    evidence=[
                        Evidence(
                            f"read Model Number characteristic (0x2A24) directly from the "
                            f"device: “{model}”"
                        )
                    ]
                    + ([Evidence(f"Manufacturer Name (0x2A29): “{vendor}”")] if vendor else []),
                    vendor=vendor,
                    matcher="gatt_probe",
                    score=1.0,
                )
            )
        elif vendor:
            out.append(
                Guess(
                    label=f"{vendor} device",
                    confidence=Confidence.HIGH,
                    evidence=[Evidence(f"read Manufacturer Name (0x2A29): “{vendor}”")],
                    vendor=vendor,
                    matcher="gatt_probe",
                    score=0.85,
                )
            )
        return out


def is_allowed(address: str, allowlist_only: bool, mine: set[str]) -> tuple[bool, str]:
    if not allowlist_only:
        return True, ""
    if address.upper() in {m.upper() for m in mine}:
        return True, ""
    return False, (
        f"{address} is not marked as your own hardware and allowlist mode is on. "
        "Mark it as yours in the device panel, or pass --any to override for this call."
    )


async def probe(
    address: str,
    timeout: float = 20.0,
    read_values: bool = True,
    adapter: str | None = None,
) -> ProbeResult:
    """Connect once, enumerate GATT, read the safe informational values, disconnect."""
    started = time.time()
    result = ProbeResult(address=address, success=False, started_at=started)

    try:
        from bleak import BleakClient
    except ImportError:
        result.error = "bleak is not installed, so probing is unavailable."
        result.remedy = "pip install bleak"
        return result

    kwargs: dict[str, Any] = {"timeout": timeout}
    if adapter:
        kwargs["adapter"] = adapter

    try:
        async with BleakClient(address, **kwargs) as client:
            for service in client.services:
                entry: dict[str, Any] = {
                    "uuid": str(service.uuid).upper(),
                    "name": service_name(str(service.uuid)) or service.description,
                    "characteristics": [],
                }
                for char in service.characteristics:
                    short = str(char.uuid).upper()
                    # Collapse to 16-bit only for genuine Bluetooth-base UUIDs;
                    # a blind [4:8] slice would fold a vendor 128-bit UUID whose
                    # chars happen to read "2A19" into the battery characteristic
                    # and read/decode it as the wrong standard field.
                    short16 = normalize_uuid(short)
                    citem: dict[str, Any] = {
                        "uuid": short,
                        "name": characteristic_name(short) or char.description,
                        "properties": list(char.properties),
                    }
                    if (
                        read_values
                        and "read" in char.properties
                        and short16 in READABLE_CHARACTERISTICS
                        and short16 not in SKIP_CHARACTERISTICS
                    ):
                        try:
                            raw = await client.read_gatt_char(char)
                            citem["value_hex"] = bytes(raw).hex()
                            text = _decode_value(short16, bytes(raw))
                            citem["value"] = text
                            result.device_info[READABLE_CHARACTERISTICS[short16]] = text
                        except Exception as exc:
                            citem["read_error"] = str(exc)
                    entry["characteristics"].append(citem)
                result.services.append(entry)
        result.success = True
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.remedy = (
            "The device may not be connectable, may already be connected to something "
            "else, or may have moved out of range. Devices that advertise as "
            "non-connectable — beacons and most trackers — cannot be probed at all."
        )

    result.duration = time.time() - started
    return result


def _decode_value(uuid16: str, raw: bytes) -> str:
    if uuid16 == "2A19" and raw:
        return f"{raw[0]}%"
    if uuid16 == "2A01" and len(raw) >= 2:
        from blemon.decode.assigned import appearance_name

        return appearance_name(int.from_bytes(raw[:2], "little"))
    if uuid16 == "2A50" and len(raw) >= 7:
        source = raw[0]
        vendor = int.from_bytes(raw[1:3], "little")
        product = int.from_bytes(raw[3:5], "little")
        version = int.from_bytes(raw[5:7], "little")
        origin = "Bluetooth SIG" if source == 1 else "USB Implementers Forum"
        return f"vendor 0x{vendor:04X} ({origin}), product 0x{product:04X}, version {version}"
    text = raw.decode("utf-8", errors="replace").strip("\x00").strip()
    return text if text else raw.hex()
