"""How a Sniffle dongle's replies are read off the wire.

The bug these cover: a correctly flashed SONOFF ZBDongle-P was reported as
"probably not flashed with Sniffle yet". The dongle was answering the version
query every time, within about 2ms, at the first rate tried. What was wrong was
the recognition test.

A measurement message body is ``[length][measurement type][payload...]``. The
old test looked for the sub-type at the length's offset and expected 0 there,
so it could never match: a version measurement's length is 5 and its sub-type
is also 5. Reading the payload as UTF-8 was wrong for the same reason — it is
four bytes of major, minor, revision and API level.

``VERSION_REPLY_LINE`` below is a byte-exact recording from a CC2652P running
Sniffle 1.11.0, so these tests fail against the reading that shipped. Packet
lines are synthesised rather than recorded: real ones carry the advertising
addresses of whoever was nearby, which have no business in a repository.
"""

from __future__ import annotations

import base64

import pytest

from blemon.capture import sniffle
from blemon.capture.sniffle import (
    MEAS_CHANMAP,
    MEAS_INTERVAL,
    MEAS_VERSION,
    MSG_MEASUREMENT,
    MSG_PACKET,
    SNIFFLE_TRAFFIC_THRESHOLD,
    FirmwareProbe,
    SniffleBackend,
    parse_version_measurement,
    probe_firmware,
    probe_firmware_any,
)

#: Recorded from /dev/cu.usbserial-2140, a SONOFF ZBDongle-P flashed with
#: Sniffle 1.11.0, in reply to CMD_VERSION. Decodes to
#: ``03 14 05 05 01 0b 00 00``: word count 3, message type 0x14, then a body of
#: length 5 whose sub-type is 5 (version), payload 1.11.0 at API level 0.
VERSION_REPLY_LINE = b"AxQFBQELAAA=\r\n"
VERSION_REPLY_BODY = bytes([0x05, MEAS_VERSION, 1, 11, 0, 0])


def wire(msg_type: int, body: bytes) -> bytes:
    """Frame a message the way the firmware does, for synthesised replies."""
    word_count = (len(body) + 1 + 3) // 3
    return base64.b64encode(bytes([word_count, msg_type]) + body) + b"\r\n"


def packet_line(seq: int = 0) -> bytes:
    """A MSG_PACKET with a body that is well-formed but nobody's real traffic."""
    return wire(MSG_PACKET, bytes([seq]) + bytes(20))


class FakeSerial:
    """Enough of a pyserial Serial for probe_firmware."""

    def __init__(self, lines: list[bytes]) -> None:
        self._lines = list(lines)
        self.written: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written.append(data)

    def readline(self) -> bytes:
        return self._lines.pop(0) if self._lines else b""

    def close(self) -> None:
        self.closed = True


def install_serial(monkeypatch: pytest.MonkeyPatch, lines: list[bytes]) -> FakeSerial:
    import serial

    fake = FakeSerial(lines)
    monkeypatch.setattr(serial, "Serial", lambda *a, **k: fake)
    return fake


def install_unopenable(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> None:
    import serial

    def boom(*a, **k):
        raise exc

    monkeypatch.setattr(serial, "Serial", boom)


# -- reading a version measurement ---------------------------------------------


def test_recorded_version_reply_is_recognised(monkeypatch):
    """The regression test: this exact line came back and was called silence."""
    fake = install_serial(monkeypatch, [VERSION_REPLY_LINE])
    probe = probe_firmware("/dev/fake", 2_000_000, timeout=0.05)
    assert probe.version == "1.11.0"
    assert probe.baudrate == 2_000_000
    assert probe.unreachable == ""
    assert fake.closed, "the port must be released whatever the outcome"


def test_the_version_command_is_what_gets_sent(monkeypatch):
    fake = install_serial(monkeypatch, [VERSION_REPLY_LINE])
    probe_firmware("/dev/fake", 2_000_000, timeout=0.05)
    assert fake.written == [base64.b64encode(bytes([1, sniffle.CMD_VERSION])) + b"\r\n"]


def test_version_payload_is_four_bytes_not_text():
    assert parse_version_measurement(VERSION_REPLY_BODY) == "1.11.0"


def test_length_byte_is_not_read_as_the_measurement_type():
    """The precise confusion that caused the bug, in both directions."""
    # Sub-type 5 sitting behind a length byte that is also 5 — must be read.
    assert parse_version_measurement(bytes([5, MEAS_VERSION, 2, 0, 1, 3])) == "2.0.1"
    # A different measurement that happens to have length 5 — must not be.
    assert parse_version_measurement(bytes([5, MEAS_CHANMAP, 1, 11, 0, 0])) is None
    # An interval measurement, whose length byte is where the old test looked.
    assert parse_version_measurement(bytes([3, MEAS_INTERVAL, 0x18, 0x00])) is None


def test_a_measurement_whose_length_disagrees_is_rejected():
    """The firmware's own length invariant, used here to reject stray bytes."""
    assert parse_version_measurement(bytes([9, MEAS_VERSION, 1, 11, 0, 0])) is None
    assert parse_version_measurement(bytes([2, MEAS_VERSION, 1])) is None


def test_backend_learns_the_version_from_a_live_measurement():
    """The same misreading sat in the capture path, where it left `unknown`."""
    backend = SniffleBackend(port="/dev/fake", baudrate=2_000_000)
    backend._dispatch(None, MSG_MEASUREMENT, VERSION_REPLY_BODY)
    assert backend._firmware == "1.11.0"
    assert "firmware 1.11.0" in backend.capabilities.description


def test_other_measurements_do_not_disturb_the_known_version():
    backend = SniffleBackend(port="/dev/fake", baudrate=2_000_000)
    backend._dispatch(None, MSG_MEASUREMENT, VERSION_REPLY_BODY)
    backend._dispatch(None, MSG_MEASUREMENT, bytes([3, MEAS_INTERVAL, 0x18, 0x00]))
    backend._dispatch(None, MSG_MEASUREMENT, b"")
    assert backend._firmware == "1.11.0"


# -- the packet stream as the other line of evidence ---------------------------


def test_streaming_packets_alone_prove_the_firmware_is_running(monkeypatch):
    """A sniffer visibly sniffing is not "probably not flashed", version or no."""
    install_serial(monkeypatch, [packet_line(i) for i in range(SNIFFLE_TRAFFIC_THRESHOLD)])
    probe = probe_firmware("/dev/fake", 2_000_000, timeout=0.05)
    assert probe.version is None
    assert probe.sniffle_traffic is True
    assert probe.is_sniffle is True
    assert probe.baudrate == 2_000_000, "the rate it streamed at is the right rate"
    assert probe.unreachable == ""


def test_one_lucky_decode_is_not_proof_of_life(monkeypatch):
    install_serial(monkeypatch, [packet_line(0)])
    probe = probe_firmware("/dev/fake", 2_000_000, timeout=0.05)
    assert probe.is_sniffle is False
    assert probe.baudrate is None


def test_noise_at_the_wrong_rate_is_not_read_as_sniffle(monkeypatch):
    """Garbage bytes are what a wrong baud rate actually produces."""
    install_serial(
        monkeypatch,
        [
            b"\xff\xfe\x01\x80 not base64 at all\r\n",
            b"////////\r\n",  # decodes cleanly, but to no known message type
            b"AAAAAAAA\r\n",
            b"@@@@\r\n",
            bytes([0x92, 0x4A, 0x25]) + b"\r\n",
        ],
    )
    probe = probe_firmware("/dev/fake", 2_000_000, timeout=0.05)
    assert probe.is_sniffle is False
    assert probe.version is None
    assert probe.unreachable == "", "the port opened, so this is silence not failure"


# -- the invariant: silence and unreachability stay separate -------------------


def test_a_silent_port_is_reported_as_silence(monkeypatch):
    install_serial(monkeypatch, [])
    probe = probe_firmware("/dev/fake", 2_000_000, timeout=0.05)
    assert probe.version is None
    assert probe.is_sniffle is False
    assert probe.unreachable == "", "nothing came back, but the port did open"


def test_a_port_that_will_not_open_says_nothing_about_firmware(monkeypatch):
    install_unopenable(monkeypatch, OSError("[Errno 16] Resource busy"))
    probe = probe_firmware("/dev/fake", 2_000_000, timeout=0.05)
    assert probe.unreachable
    assert probe.is_sniffle is False


def test_the_rate_search_stops_once_the_dongle_is_heard(monkeypatch):
    """Sniffle framing only decodes at the real rate, so hearing it settles it."""
    asked: list[int] = []

    def fake_probe(port, baudrate=2_000_000, timeout=0.4):
        asked.append(baudrate)
        return FirmwareProbe(baudrate=baudrate, sniffle_traffic=True)

    monkeypatch.setattr(sniffle, "probe_firmware", fake_probe)
    probe = probe_firmware_any("/dev/fake")
    assert probe.is_sniffle is True
    assert asked == [2_000_000]


def test_a_streaming_rate_is_adopted_without_a_version_reply(monkeypatch):
    """Baud negotiation should trust the stream as readily as a version reply."""
    monkeypatch.setattr(
        sniffle,
        "probe_firmware_any",
        lambda *a, **k: FirmwareProbe(baudrate=921_600, sniffle_traffic=True),
    )
    backend = SniffleBackend(port="/dev/fake")
    assert backend._negotiate_baudrate((2_000_000, 921_600)) == 921_600


# -- what the user is finally told ---------------------------------------------


def sniffer_findings(monkeypatch: pytest.MonkeyPatch, probe: FirmwareProbe) -> list:
    """Run doctor's sniffer check against one hypothetical probe result."""
    from blemon.capture import nrf_sniffer
    from blemon.cli.doctor import Report, _check_sniffers

    found = sniffle.DetectedSniffer(
        port="/dev/fake",
        description="SONOFF ZBDongle-P (CC2652P) on /dev/fake",
        vid=0x10C4,
        pid=0xEA60,
        baudrate=2_000_000,
    )
    monkeypatch.setattr(sniffle, "detect_sniffers", lambda: [found])
    monkeypatch.setattr(sniffle, "probe_firmware_any", lambda *a, **k: probe)
    monkeypatch.setattr(nrf_sniffer, "detect_nordic", lambda: [])
    report = Report()
    _check_sniffers(report)
    return [f for f in report.findings if "Sniffle" in f.title]


def test_doctor_reports_a_working_dongle_with_its_version(monkeypatch):
    (finding,) = sniffer_findings(
        monkeypatch,
        FirmwareProbe(version="1.11.0", baudrate=2_000_000, sniffle_traffic=True),
    )
    assert finding.level == "ok"
    assert "1.11.0" in finding.detail
    assert "2000000" in finding.detail


def test_doctor_accepts_a_sniffer_that_is_visibly_sniffing(monkeypatch):
    (finding,) = sniffer_findings(
        monkeypatch, FirmwareProbe(baudrate=2_000_000, sniffle_traffic=True)
    )
    assert finding.level == "ok"
    assert "not flashed" not in finding.detail


def test_doctor_never_tells_you_to_reflash_a_port_it_could_not_open(monkeypatch):
    """The invariant: unreachable is not a verdict on the firmware."""
    (finding,) = sniffer_findings(
        monkeypatch, FirmwareProbe(unreachable="[Errno 16] Resource busy")
    )
    assert finding.level == "info"
    assert "not flashed" not in finding.detail
    assert "Flashing Sniffle firmware" not in finding.remedy


def test_doctor_still_suspects_the_firmware_when_nothing_answers(monkeypatch):
    """And the other half of it: real silence must keep saying so."""
    (finding,) = sniffer_findings(monkeypatch, FirmwareProbe())
    assert finding.level == "warn"
    assert "not flashed" in finding.detail
    assert "Flashing Sniffle firmware" in finding.remedy
