"""Baud-rate negotiation for Sniffle hardware.

The bug these cover: a SONOFF ZBDongle-P was assumed to run at 921600 because
some 2022 units shipped with a CP2102 (non-N) bridge. Current units have the
CP2102N and run Sniffle's standard 2 Mbaud build, and the two enumerate
identically over USB. Probing at the wrong rate is silent — the port opens and
nothing comes back — so a correctly flashed dongle was reported as never having
been flashed.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from blemon.capture import sniffle
from blemon.capture.sniffle import (
    SNIFFLE_BAUD_RATES,
    FirmwareProbe,
    detect_sniffers,
    probe_firmware_any,
)


class FakePort(SimpleNamespace):
    """Enough of a pyserial ListPortInfo for detect_sniffers()."""


def _install_ports(monkeypatch: pytest.MonkeyPatch, ports: list[FakePort]) -> None:
    """Patch the attribute, not sys.modules.

    ``detect_sniffers`` does ``from serial.tools import list_ports``, which binds
    the attribute already present on the package whenever anything has imported
    it before us. Replacing the sys.modules entry therefore works in isolation
    and silently does nothing in a full test run.
    """
    from serial.tools import list_ports

    monkeypatch.setattr(list_ports, "comports", lambda: ports)


SONOFF = FakePort(
    device="/dev/cu.usbserial-2140",
    vid=0x10C4,
    pid=0xEA60,
    product="Sonoff Zigbee 3.0 USB Dongle Plus",
)


def test_sonoff_dongle_offers_both_rates_fastest_first(monkeypatch):
    """The CP2102N is the common case now, so 2 Mbaud is tried before 921600."""
    _install_ports(monkeypatch, [SONOFF])
    found = detect_sniffers()
    assert len(found) == 1
    assert found[0].baud_candidates == (2_000_000, 921_600)
    assert found[0].baudrate == 2_000_000, "preferred rate must be the fastest"


def test_launchpad_is_two_mbaud_only(monkeypatch):
    """Only the CP210x-bridged dongles have a slow variant to worry about."""
    _install_ports(
        monkeypatch,
        [FakePort(device="/dev/ttyACM0", vid=0x0451, pid=0xBEF3, product="XDS110")],
    )
    assert detect_sniffers()[0].baud_candidates == (2_000_000,)


def test_probe_finds_firmware_at_the_slower_rate(monkeypatch):
    """A dongle running the _1M build is still found, just not on the first try."""
    asked: list[int] = []

    def fake_probe(port, baudrate=2_000_000, timeout=0.4):
        asked.append(baudrate)
        if baudrate == 921_600:
            return FirmwareProbe(version="1.11.0", baudrate=baudrate)
        return FirmwareProbe()

    monkeypatch.setattr(sniffle, "probe_firmware", fake_probe)
    probe = probe_firmware_any("/dev/null", SNIFFLE_BAUD_RATES)
    assert probe.version == "1.11.0"
    assert probe.baudrate == 921_600
    assert asked == [2_000_000, 921_600]


def test_probe_stops_at_the_first_rate_that_answers(monkeypatch):
    """The common case costs one query, not one per candidate rate."""
    asked: list[int] = []

    def fake_probe(port, baudrate=2_000_000, timeout=0.4):
        asked.append(baudrate)
        return FirmwareProbe(version="1.11.0", baudrate=baudrate)

    monkeypatch.setattr(sniffle, "probe_firmware", fake_probe)
    assert probe_firmware_any("/dev/null").baudrate == 2_000_000
    assert asked == [2_000_000]


def test_silence_at_every_rate_reports_silence_not_unreachability(monkeypatch):
    """Only this outcome may be read as 'probably not flashed'."""
    monkeypatch.setattr(
        sniffle, "probe_firmware", lambda *a, **k: FirmwareProbe()
    )
    probe = probe_firmware_any("/dev/null")
    assert probe.version is None
    assert probe.unreachable == ""


def test_busy_port_never_reads_as_missing_firmware(monkeypatch):
    """A port held open by `blemon serve` says nothing about what is flashed.

    Collapsing this into 'not flashed' is what tells someone to reflash working
    hardware, so it stays distinguishable no matter how many rates were tried.
    """
    monkeypatch.setattr(
        sniffle,
        "probe_firmware",
        lambda *a, **k: FirmwareProbe(unreachable="Resource busy"),
    )
    probe = probe_firmware_any("/dev/null")
    assert probe.version is None
    assert probe.unreachable == "Resource busy"


def test_one_rate_rejected_by_the_driver_does_not_mask_a_real_silence(monkeypatch):
    """Some drivers refuse a nonstandard rate outright; that is not the verdict."""

    def fake_probe(port, baudrate=2_000_000, timeout=0.4):
        if baudrate == 2_000_000:
            return FirmwareProbe(unreachable="invalid baud rate")
        return FirmwareProbe()

    monkeypatch.setattr(sniffle, "probe_firmware", fake_probe)
    probe = probe_firmware_any("/dev/null")
    assert probe.unreachable == "", "the port opened at 921600, so it is reachable"


def test_explicit_baudrate_is_never_second_guessed(monkeypatch):
    """`--baud` is an override, so it must not trigger a probe."""

    def explode(*a, **k):
        raise AssertionError("probed despite an explicit --baud")

    monkeypatch.setattr(sniffle, "probe_firmware_any", explode)
    backend = sniffle.SniffleBackend(port="/dev/null", baudrate=115_200)
    assert backend.baudrate == 115_200


def test_baud_flag_is_omitted_when_unset(monkeypatch):
    """The nRF backend has its own 1 Mbaud default; None must not overwrite it."""
    import importlib

    # `blemon.cli` re-exports the main() function under the name `main`, so
    # `import blemon.cli.main` would bind the function, not this module.
    main_mod = importlib.import_module("blemon.cli.main")

    args = main_mod.build_parser().parse_args(["scan", "--backend", "synthetic"])
    assert args.serial_baud is None

    seen: dict[str, object] = {}
    original = main_mod.create

    def spy(name, **kw):
        seen.update(kw)
        return original(name, **kw)

    monkeypatch.setattr(main_mod, "create", spy)
    main_mod.make_backend(args)
    assert "baudrate" not in seen


def test_baud_flag_is_passed_through_when_given():
    from blemon.cli.main import build_parser

    args = build_parser().parse_args(["scan", "--baud", "921600"])
    assert args.serial_baud == 921_600
