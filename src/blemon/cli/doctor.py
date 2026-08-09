"""``blemon doctor`` — say exactly what this setup can and cannot see, and why.

The single most useful command in the tool. A monitor that shows an empty
screen is indistinguishable from a quiet room, so there has to be one command
that tells you which you are looking at, and what to do about it.

Every finding carries a remedy. "Permission denied" on its own is not a
diagnosis.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any

from blemon import __version__
from blemon.capture import available_backends, create
from blemon.capture.base import CaptureError
from blemon.decode import registered
from blemon.identity import registered_matchers

OK = "ok"
WARN = "warn"
FAIL = "fail"
INFO = "info"


@dataclass
class Finding:
    level: str
    title: str
    detail: str = ""
    remedy: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "title": self.title,
            "detail": self.detail,
            "remedy": self.remedy,
        }


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    backends: dict[str, str] = field(default_factory=dict)
    capabilities: dict[str, Any] | None = None
    chosen_backend: str | None = None

    def add(self, level: str, title: str, detail: str = "", remedy: str = "") -> None:
        self.findings.append(Finding(level, title, detail, remedy))

    @property
    def worst(self) -> str:
        for level in (FAIL, WARN, OK):
            if any(f.level == level for f in self.findings):
                return level
        return INFO

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": __version__,
            "platform": f"{platform.system()} {platform.release()}",
            "python": sys.version.split()[0],
            "worst": self.worst,
            "chosen_backend": self.chosen_backend,
            "backends": self.backends,
            "capabilities": self.capabilities,
            "findings": [f.to_dict() for f in self.findings],
        }


FLASH_SNIFFLE = """Flashing Sniffle firmware:
  1. Download a release from https://github.com/nccgroup/Sniffle/releases
  2. SONOFF ZBDongle-P: hold BOOT, plug in, then
       python -m pip install cc2538-bsl
       cc2538-bsl -p /dev/ttyUSB0 -evw sniffle_cc1352p1_cc2652p1.hex
     TI LaunchPad: use UniFlash, or drag the .hex onto the DAPLink drive.
  3. Unplug, replug, and run `blemon doctor` again."""

FLASH_NRF = """Flashing the Nordic nRF Sniffer:
  1. Download "nRF Sniffer for Bluetooth LE" from nordicsemi.com
  2. nRF52840 Dongle: press the reset button so the LED pulses red, then
       nrfutil pkg generate --hw-version 52 --sd-req 0x00 \\
         --application sniffer_nrf52840dongle_nrf52840_*.hex sniffer.zip
       nrfutil dfu usb-serial -pkg sniffer.zip -p /dev/ttyACM0
  3. Unplug, replug, and run `blemon doctor` again."""


def run_doctor(check_backend: str | None = None) -> Report:
    report = Report()
    system = platform.system()

    report.add(
        INFO,
        f"ble-monitor {__version__} on {system} {platform.release()}, "
        f"Python {sys.version.split()[0]}",
    )

    # -- platform-specific radio access -----------------------------------

    if system == "Linux":
        _check_linux(report)
    elif system == "Darwin":
        _check_macos(report)
    else:
        report.add(
            WARN,
            f"{system} is not a supported platform",
            "Only macOS and Linux are targeted. Nothing here is deliberately "
            "POSIX-only, but no radio backend is expected to work.",
            "Run with `--backend synthetic` to see what the tool does.",
        )

    _check_sniffers(report)

    # -- backend availability ---------------------------------------------

    report.backends = available_backends()
    usable = [n for n, why in report.backends.items() if why == ""]
    real = [n for n in usable if n != "synthetic"]
    if real:
        report.add(
            OK,
            f"Usable capture backends: {', '.join(real)}",
            "The most capable one is chosen automatically.",
        )
    else:
        report.add(
            WARN,
            "No real capture backend is available",
            "Only the synthetic environment can run, which is generated locally "
            "and is not a radio.",
            "The findings above say what is missing. `blemon scan --backend synthetic` "
            "works regardless and shows you exactly what the tool does.",
        )

    # -- can the chosen backend actually start? ---------------------------

    target = check_backend or (real[0] if real else "synthetic")
    report.chosen_backend = target
    try:
        backend = create(target)
        caps = backend.capabilities
        report.capabilities = {
            "name": caps.name,
            "backend": target,
            **caps.to_dict(),
            "missing": caps.missing(),
        }
        report.add(OK, f"Backend `{target}` constructed", caps.name)
    except CaptureError as exc:
        report.add(FAIL, f"Backend `{target}` could not be created", str(exc), exc.remedy)
    except Exception as exc:  # noqa: BLE001
        report.add(FAIL, f"Backend `{target}` raised {type(exc).__name__}", str(exc))

    # -- decoders and matchers --------------------------------------------

    decoders = registered()
    report.add(
        OK,
        f"{len(decoders['manufacturer'])} manufacturer decoders, "
        f"{len(decoders['service_data'])} service-data decoders, "
        f"{len(registered_matchers())} identification matchers loaded",
    )

    # -- storage -----------------------------------------------------------

    from blemon.store import default_db_path

    try:
        path = default_db_path()
        writable = os.access(path.parent, os.W_OK)
        report.add(
            OK if writable else FAIL,
            f"Storage at {path}",
            "Writable." if writable else "Not writable.",
            "" if writable else f"Check permissions on {path.parent}.",
        )
    except OSError as exc:
        report.add(FAIL, "Could not prepare the storage directory", str(exc))

    # -- the dashboard bundle ---------------------------------------------

    from blemon.service import web_asset_dir

    if web_asset_dir() is None:
        report.add(
            WARN,
            "The web dashboard is not bundled in this install",
            "The API and CLI work fully; only the browser UI is missing. This "
            "happens when running from a source checkout that has not been built.",
            "npm --prefix web install && npm --prefix web run build",
        )
    else:
        report.add(OK, "Web dashboard bundle present")

    return report


def _check_linux(report: Report) -> None:
    from blemon.capture.hci_linux import _adapter_is_up, _hci_devices

    devices = _hci_devices()
    if not devices:
        report.add(
            FAIL,
            "No Bluetooth adapter found",
            "Nothing under /sys/class/bluetooth.",
            "Check `rfkill list` and `dmesg | grep -i blue`. On a Raspberry Pi, make "
            "sure the onboard radio is not disabled in /boot/config.txt, and try "
            "`sudo rfkill unblock bluetooth`.",
        )
        return

    names = ", ".join(f"hci{d}" for d in devices)
    up = _adapter_is_up(devices[0])
    report.add(OK, f"Bluetooth adapter present: {names}", f"hci{devices[0]} is "
               + ("up" if up else "down" if up is False else "in an unknown state"))

    # Capability check — the difference between working and a confusing failure.
    exe = os.path.realpath(sys.executable)
    caps_ok = False
    getcap = shutil.which("getcap")
    if getcap:
        import subprocess

        try:
            out = subprocess.run(
                [getcap, exe], capture_output=True, text=True, timeout=5
            ).stdout
            caps_ok = "cap_net_raw" in out
        except (OSError, subprocess.SubprocessError):
            caps_ok = False

    if os.geteuid() == 0:
        report.add(
            OK,
            "Running as root, so raw HCI access will work",
            "Granting capabilities instead is safer and works just as well.",
            f"sudo setcap 'cap_net_raw,cap_net_admin+eip' {exe}",
        )
    elif caps_ok:
        report.add(OK, "cap_net_raw is granted on this Python interpreter", exe)
    else:
        report.add(
            WARN,
            "Raw HCI access is probably not permitted",
            f"{exe} does not have cap_net_raw, and you are not root. Capture will "
            "fail with a permission error.",
            f"sudo setcap 'cap_net_raw,cap_net_admin+eip' {exe}\n"
            "     (prefer this over running the whole tool with sudo)",
        )

    # BlueZ holding the adapter is the other common cause of a confusing failure.
    if shutil.which("systemctl"):
        import subprocess

        try:
            state = subprocess.run(
                ["systemctl", "is-active", "bluetooth"],
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
            if state == "active":
                report.add(
                    INFO,
                    "BlueZ (bluetooth.service) is running",
                    "ble-monitor will briefly power the adapter down to take exclusive "
                    "control, and restore it on exit. If that fails you can run "
                    "read-only instead.",
                    "blemon scan --hci-mode monitor",
                )
        except (OSError, subprocess.SubprocessError):
            pass


def _check_macos(report: Report) -> None:
    report.add(
        WARN,
        "macOS hides MAC addresses from applications",
        "CoreBluetooth gives each device an opaque per-application UUID instead of "
        "its hardware address. Address-privacy analysis, correlation across address "
        "rotation, and comparing captures between machines are all unavailable here. "
        "The raw advertising payload is also not exposed, so what you see is "
        "reconstructed from the OS's parsed summary.",
        "For the full picture, run the capture service on a Raspberry Pi and point "
        "this Mac's dashboard at it:  blemon serve --host 0.0.0.0  on the Pi, then "
        "open http://<pi>:8420 here.",
    )
    try:
        import bleak  # noqa: F401

        report.add(OK, "bleak is installed")
    except ImportError:
        report.add(
            FAIL,
            "bleak is not installed, so the Mac's radio cannot be used",
            remedy="pip install bleak",
        )
    report.add(
        INFO,
        "macOS will ask for Bluetooth permission the first time you scan",
        "If no devices ever appear, permission was probably denied.",
        "System Settings › Privacy & Security › Bluetooth — enable your terminal "
        "or the app you launched this from.",
    )


def _check_sniffers(report: Report) -> None:
    try:
        import serial  # noqa: F401
    except ImportError:
        report.add(
            WARN,
            "pyserial is not installed, so no sniffer can be used",
            remedy="pip install pyserial",
        )
        return

    from blemon.capture.nrf_sniffer import detect_nordic
    from blemon.capture.sniffle import detect_sniffers, probe_firmware

    sniffle = detect_sniffers()
    nordic = detect_nordic()

    if sniffle:
        for found in sniffle:
            # A device with the right USB identity is not necessarily flashed
            # with Sniffle — a factory SONOFF ships with Zigbee firmware. Ask it.
            probe = probe_firmware(found.port, found.baudrate)
            if probe.version:
                report.add(
                    OK,
                    f"Sniffle sniffer: {found.description}",
                    f"Responded to a version query (firmware: {probe.version}). This is "
                    "the backend that can follow connections.",
                )
            elif probe.unreachable:
                # Could not talk to it at all. That says nothing about the
                # firmware, and telling the user to reflash a dongle that is
                # merely busy — because their own `blemon serve` has it open —
                # would be actively wrong.
                report.add(
                    INFO,
                    f"Sniffle-compatible hardware: {found.description}",
                    f"The USB identity matches, but the port could not be opened to "
                    f"check the firmware ({probe.unreachable}). This is usually another "
                    "process already using it — a running `blemon serve` — or missing "
                    "permission on the serial device (on Linux, add yourself to the "
                    "`dialout` group and log back in).",
                )
            else:
                report.add(
                    WARN,
                    f"Sniffle-compatible hardware: {found.description}",
                    "The USB identity matches, but it did not answer a version query — "
                    "it is probably not flashed with Sniffle yet (a factory SONOFF "
                    "dongle ships with Zigbee firmware).",
                    FLASH_SNIFFLE,
                )
    if nordic:
        for found in nordic:
            is_sniffer = found.firmware == "sniffer"
            report.add(
                OK if is_sniffer else WARN,
                f"Nordic device: {found.description}",
                ""
                if is_sniffer
                else "This looks like a dongle in bootloader mode rather than running "
                "sniffer firmware. It will connect but send nothing.",
                "" if is_sniffer else FLASH_NRF,
            )

    if not sniffle and not nordic:
        report.add(
            INFO,
            "No sniffer hardware attached",
            "Without one you can see every advertisement in range, but not what "
            "devices say to each other once they connect — that traffic hops across "
            "37 data channels and a host adapter cannot follow it.",
            "Recommended: a SONOFF ZBDongle-P (the CC2652P one — the ZBDongle-E is "
            "different silicon and will not work) or a TI CC1352P7 LaunchPad, flashed "
            "with Sniffle.\n\n" + FLASH_SNIFFLE,
        )

    # Serial port permissions trip people up constantly on Linux.
    if platform.system() == "Linux" and (sniffle or nordic):
        port = (sniffle[0].port if sniffle else nordic[0].port)
        if not os.access(port, os.R_OK | os.W_OK):
            report.add(
                FAIL,
                f"No permission to use {port}",
                "The sniffer is detected but cannot be opened.",
                "sudo usermod -aG dialout $USER   # then log out and back in",
            )
        else:
            report.add(OK, f"{port} is readable and writable")
