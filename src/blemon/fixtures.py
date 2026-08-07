"""Realistic advertisement fixtures.

One module, two jobs:

* the synthetic capture backend uses these to produce a believable radio
  environment with no hardware attached, so the whole tool can be driven and
  demonstrated before a sniffer arrives;
* the test suite uses the same builders, so every decoder is exercised against
  payloads whose framing is constructed the same way a real controller
  constructs it — length bytes computed, not hand-typed.

Nothing here is captured from a real person's device. The payload *shapes* are
real; the identifiers are invented.
"""

from __future__ import annotations

import hashlib
import math
import random
import struct
from dataclasses import dataclass, field

from blemon.models import AddressType, Advertisement, PduType, classify_address

# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------


def ad(type_code: int, value: bytes) -> bytes:
    """One AD structure with its length byte computed."""
    if len(value) > 254:
        raise ValueError("AD structure value too long")
    return bytes([len(value) + 1, type_code]) + value


def payload(*structures: bytes) -> bytes:
    return b"".join(structures)


def flags(value: int = 0x06) -> bytes:
    """0x06 = LE General Discoverable + BR/EDR Not Supported, the common case."""
    return ad(0x01, bytes([value]))


def complete_name(name: str) -> bytes:
    return ad(0x09, name.encode("utf-8"))


def short_name(name: str) -> bytes:
    return ad(0x08, name.encode("utf-8"))


def tx_power(dbm: int) -> bytes:
    return ad(0x0A, struct.pack("<b", dbm))


def appearance(value: int) -> bytes:
    return ad(0x19, struct.pack("<H", value))


def service_uuids16(*uuids: int) -> bytes:
    return ad(0x03, b"".join(struct.pack("<H", u) for u in uuids))


def incomplete_uuids16(*uuids: int) -> bytes:
    return ad(0x02, b"".join(struct.pack("<H", u) for u in uuids))


def service_uuid128(uuid_hex: str) -> bytes:
    raw = bytes.fromhex(uuid_hex.replace("-", ""))
    return ad(0x07, raw[::-1])


def service_data16(uuid: int, body: bytes) -> bytes:
    return ad(0x16, struct.pack("<H", uuid) + body)


def manufacturer(company_id: int, body: bytes) -> bytes:
    return ad(0xFF, struct.pack("<H", company_id) + body)


def continuity(msg_type: int, body: bytes) -> bytes:
    """One Apple Continuity TLV, ready to wrap in ``manufacturer(0x004C, ...)``."""
    return bytes([msg_type, len(body)]) + body


# ---------------------------------------------------------------------------
# Ready-made payloads for each protocol we decode
# ---------------------------------------------------------------------------


def apple_nearby_info(action: int = 0x07, status: int = 0x1, data_flags: int = 0x14,
                      auth: bytes = b"\x9b\x7a\x3c") -> bytes:
    return manufacturer(0x004C, continuity(0x10, bytes([(status << 4) | action, data_flags]) + auth))


def apple_handoff(seq: int = 4207, clipboard: int = 0x00) -> bytes:
    body = bytes([clipboard]) + struct.pack("<H", seq) + b"\x2f" + bytes(10)
    return manufacturer(0x004C, continuity(0x0C, body))


def apple_airdrop() -> bytes:
    body = bytes(8) + b"\x01" + b"\x9c\x41" + b"\x00\x00" + b"\x3e\xa7" + b"\x00\x00" + b"\x00"
    return manufacturer(0x004C, continuity(0x05, body))


def apple_nearby_action(action_type: int = 0x09) -> bytes:
    return manufacturer(0x004C, continuity(0x0F, bytes([0xC0, action_type]) + b"\x1a\x2b\x3c"))


def ibeacon(uuid: str = "B9407F30-F5F8-466E-AFF9-25556B57FE6D",
            major: int = 1, minor: int = 2, power: int = -59) -> bytes:
    body = bytes.fromhex(uuid.replace("-", "")) + struct.pack(">HH", major, minor)
    body += struct.pack("<b", power)
    return manufacturer(0x004C, continuity(0x02, body))


def airpods(model: int = 0x1420, left: int = 8, right: int = 7, case: int = 5,
            lid_count: int = 42, lid_open: bool = True) -> bytes:
    body = bytes([0x01]) + struct.pack(">H", model)
    body += bytes([0x08 if lid_open else 0x00])
    body += bytes([(left << 4) | right])
    body += bytes([(0x1 << 4) | case])
    body += bytes([lid_count, 0x00, 0x00])
    body += bytes(range(16))  # the encrypted tail
    return manufacturer(0x004C, continuity(0x07, body))


def find_my(separated: bool = True, battery: int = 0) -> bytes:
    status = (battery & 0x03) << 6
    if separated:
        body = bytes([status]) + hashlib.sha256(b"invented-key").digest()[:22] + b"\x03\x00"
    else:
        status |= 0x04
        body = bytes([status, 0x00])
    return manufacturer(0x004C, continuity(0x12, body))


def apple_hotspot(battery: int = 74, bars: int = 3) -> bytes:
    body = bytes([0x01, 0x00, battery]) + struct.pack("<H", 0x0004) + bytes([bars, 0x00])
    return manufacturer(0x004C, continuity(0x0E, body))


def apple_homekit(dev_id: str = "AA:BB:CC:DD:EE:01", category: int = 5, state: int = 17) -> bytes:
    body = bytes([0x00]) + bytes(int(x, 16) for x in dev_id.split(":"))
    body += struct.pack("<HH", category, state)
    return manufacturer(0x004C, continuity(0x06, body))


def eddystone_url(url_body: str = "example", scheme: int = 0x03, suffix: int = 0x07,
                  power: int = -22) -> bytes:
    body = bytes([0x10]) + struct.pack("<b", power) + bytes([scheme])
    body += url_body.encode("ascii") + bytes([suffix])
    return payload(service_uuids16(0xFEAA), service_data16(0xFEAA, body))


def eddystone_uid(namespace: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a",
                  instance: bytes = b"\x00\x00\x00\x00\x00\x01", power: int = -20) -> bytes:
    body = bytes([0x00]) + struct.pack("<b", power) + namespace + instance + b"\x00\x00"
    return payload(service_uuids16(0xFEAA), service_data16(0xFEAA, body))


def eddystone_tlm(mv: int = 2979, temp_c: float = 21.5, adv_count: int = 250_413,
                  uptime_s: float = 903_120.0) -> bytes:
    body = bytes([0x20, 0x00]) + struct.pack(
        ">HhII", mv, int(temp_c * 256), adv_count, int(uptime_s * 10)
    )
    return payload(service_uuids16(0xFEAA), service_data16(0xFEAA, body))


def google_find_my_device(unwanted: bool = False) -> bytes:
    body = bytes([0x41 if unwanted else 0x40]) + hashlib.sha256(b"fmdn").digest()[:20]
    return payload(service_uuids16(0xFEAA), service_data16(0xFEAA, body))


def fast_pair_discoverable(model: int = 0x0001F0) -> bytes:
    return payload(
        flags(),
        service_uuids16(0xFE2C),
        service_data16(0xFE2C, model.to_bytes(3, "big")),
    )


def fast_pair_paired(battery: tuple[int, ...] = (72, 68, 90)) -> bytes:
    body = bytes([0x00])
    body += bytes([(2 << 4) | 0x0]) + b"\x11\x22"  # account key filter
    body += bytes([(1 << 4) | 0x2]) + b"\x5a"  # salt
    body += bytes([(len(battery) << 4) | 0x3]) + bytes(b & 0x7F for b in battery)
    return payload(flags(), service_uuids16(0xFE2C), service_data16(0xFE2C, body))


def microsoft_cdp(device_type: int = 15) -> bytes:
    body = bytes([0x01, (1 << 5) | device_type, 0x21, 0x0A])
    body += b"\x42\xf1\xf8\xe3"
    body += hashlib.sha256(b"cdp-device").digest()[:16]
    return manufacturer(0x0006, body)


def microsoft_swift_pair(name: str = "Surface Mouse", sub: int = 0x01) -> bytes:
    body = bytes([0x03, sub, 0x80]) + name.encode("utf-8")
    return manufacturer(0x0006, body)


def bthome(temperature: float = 21.34, humidity: float = 48.5, battery: int = 93,
           packet_id: int = 9, motion: bool | None = None) -> bytes:
    body = bytes([0x40])  # v2, unencrypted
    body += bytes([0x00, packet_id])
    body += bytes([0x01, battery])
    body += bytes([0x02]) + struct.pack("<h", int(round(temperature * 100)))
    body += bytes([0x03]) + struct.pack("<H", int(round(humidity * 100)))
    if motion is not None:
        body += bytes([0x21, 1 if motion else 0])
    return payload(flags(), service_data16(0xFCD2, body))


def xiaomi_thermometer(temperature: float = 22.4, humidity: float = 51.2,
                       packet_id: int = 33, addr: str = "A4:C1:38:11:22:33") -> bytes:
    fctrl = (1 << 4) | (1 << 6)  # MAC included, object included
    body = struct.pack("<HH", fctrl, 0x055B) + bytes([packet_id])
    body += bytes(int(x, 16) for x in addr.split(":"))[::-1]
    body += struct.pack("<HB", 0x100D, 4)
    body += struct.pack("<hH", int(temperature * 10), int(humidity * 10))
    return payload(flags(), service_data16(0xFE95, body))


def ruuvi(temperature: float = 19.36, humidity: float = 43.5, pressure: float = 1013.2,
          moves: int = 66, seq: int = 205, addr: str = "CB:B8:33:4C:88:4F") -> bytes:
    body = bytes([0x05])
    body += struct.pack(">h", int(round(temperature / 0.005)))
    body += struct.pack(">H", int(round(humidity / 0.0025)))
    body += struct.pack(">H", int(round(pressure * 100)) - 50000)
    body += struct.pack(">hhh", 4, -4, 1036)
    power = ((int(2.977 * 1000) - 1600) << 5) | ((4 + 40) // 2)
    body += struct.pack(">H", power)
    body += bytes([moves]) + struct.pack(">H", seq)
    body += bytes(int(x, 16) for x in addr.split(":"))
    return manufacturer(0x0499, body)


def govee(temperature: float = 23.4, humidity: float = 46.0, battery: int = 88) -> bytes:
    packed = int(round(temperature * 10000)) + int(round(humidity * 10))
    body = bytes([0x00]) + packed.to_bytes(3, "big") + bytes([battery])
    return manufacturer(0xEC88, body)


def tile(tile_id: bytes = b"\x0a\x1b\x2c\x3d\x4e\x5f\x60\x71") -> bytes:
    return payload(flags(), service_uuids16(0xFEED), service_data16(0xFEED, b"\x02\x00" + tile_id))


def samsung_smarttag() -> bytes:
    body = b"\x01\x00" + hashlib.sha256(b"smarttag").digest()[:10]
    return payload(flags(), service_uuids16(0xFD5A), service_data16(0xFD5A, body))


def exposure_notification() -> bytes:
    body = hashlib.sha256(b"rpi").digest()[:16] + b"\x11\x22\x33\x44"
    return payload(flags(0x1A), service_uuids16(0xFD6F), service_data16(0xFD6F, body))


def heart_rate(bpm: int = 71) -> bytes:
    return payload(
        flags(),
        complete_name("HRM-Pro"),
        service_uuids16(0x180D, 0x180F),
        service_data16(0x180D, bytes([0x06, bpm])),
        appearance(0x0341),
    )


def battery_only(pct: int = 61) -> bytes:
    return payload(flags(), service_uuids16(0x180F), service_data16(0x180F, bytes([pct])))


def unknown_vendor(counter: int = 0, company_id: int = 0x0F0F) -> bytes:
    """A device with no public spec: a stable prefix, a counter, and a nonce."""
    body = b"\xde\xad\xbe\xef" + struct.pack("<H", counter)
    body += hashlib.md5(struct.pack("<I", counter)).digest()[:4]
    return manufacturer(company_id, body)


def keyboard() -> bytes:
    return payload(
        flags(),
        complete_name("Magic Keyboard"),
        service_uuids16(0x1812, 0x180F),
        appearance(0x03C1),
        tx_power(-6),
    )


# ---------------------------------------------------------------------------
# A synthetic radio environment
# ---------------------------------------------------------------------------


@dataclass
class SyntheticDevice:
    """A believable device: an address policy, a payload generator, a distance."""

    key: str
    label: str
    address: str
    random_address: bool
    #: Seconds between advertisements.
    interval: float
    #: Nominal RSSI at rest; the walk wanders around it.
    base_rssi: int
    #: How far the RSSI wanders, in dB.
    drift: int = 6
    #: Rotate the address roughly every N seconds (RPA behaviour). None = never.
    rotate_every: float | None = None
    #: Present only between these session-relative times, in seconds.
    present_from: float = 0.0
    present_until: float = math.inf
    scan_response: bytes | None = None
    _counter: int = field(default=0, repr=False)
    _last_rotate: float = field(default=0.0, repr=False)
    _rssi: float = field(default=0.0, repr=False)

    def build(self, t: float) -> bytes:  # pragma: no cover - overridden per device
        raise NotImplementedError

    def rotate_if_due(self, t: float, rng: random.Random) -> None:
        if self.rotate_every is None:
            return
        if t - self._last_rotate >= self.rotate_every:
            self._last_rotate = t
            octets = [rng.randrange(256) for _ in range(6)]
            octets[0] = (octets[0] & 0x3F) | 0x40  # resolvable private
            self.address = ":".join(f"{b:02X}" for b in octets)

    def next_rssi(self, rng: random.Random) -> int:
        if self._rssi == 0.0:
            self._rssi = float(self.base_rssi)
        self._rssi += rng.gauss(0, 1.4)
        self._rssi = max(
            self.base_rssi - self.drift, min(self.base_rssi + self.drift, self._rssi)
        )
        return int(round(self._rssi))


@dataclass
class _Fn(SyntheticDevice):
    fn: object = None

    def build(self, t: float) -> bytes:
        self._counter += 1
        return self.fn(self, t)  # type: ignore[misc]


def _device(key, label, address, random_address, interval, rssi, fn, **kw) -> SyntheticDevice:
    return _Fn(
        key=key,
        label=label,
        address=address,
        random_address=random_address,
        interval=interval,
        base_rssi=rssi,
        fn=fn,
        **kw,
    )


def default_population() -> list[SyntheticDevice]:
    """A plausible café: a few phones, some earbuds, beacons, sensors, a tracker."""
    return [
        _device(
            "iphone", "iPhone (owner's)", "5E:11:A3:7C:90:22", True, 0.35, -47,
            lambda d, t: payload(
                flags(0x1A),
                apple_nearby_info(action=0x07 if int(t) % 20 < 12 else 0x03,
                                  auth=struct.pack("<I", d._counter)[:3]),
            ),
            rotate_every=900,
        ),
        _device(
            "iphone2", "iPhone (someone else's)", "6A:9C:04:1F:B7:3D", True, 0.6, -72,
            lambda d, t: payload(
                flags(0x1A),
                apple_nearby_info(action=0x03, status=0x0, data_flags=0x0C,
                                  auth=struct.pack("<I", d._counter * 7)[:3]),
                apple_handoff(seq=1000 + d._counter),
            ),
            rotate_every=900,
            present_from=45,
        ),
        _device(
            "airpods", "AirPods Pro", "48:D8:12:6C:03:9E", True, 0.5, -55,
            lambda d, t: payload(
                flags(0x1A),
                airpods(left=max(1, 9 - int(t // 400)), right=max(1, 8 - int(t // 400)),
                        case=6, lid_count=17, lid_open=(int(t) % 60 < 8)),
            ),
            rotate_every=1800,
        ),
        _device(
            "airtag", "AirTag (unknown owner)", "72:0B:5D:E1:44:8C", True, 2.0, -66,
            lambda d, t: payload(flags(0x06), find_my(separated=True, battery=1)),
            rotate_every=900,
        ),
        _device(
            "tile", "Tile tracker", "C4:19:D1:88:20:7A", False, 1.2, -78,
            lambda d, t: tile(),
        ),
        _device(
            "laptop", "Windows laptop", "3C:9C:0F:44:21:AB", True, 1.5, -63,
            lambda d, t: payload(flags(0x06), microsoft_cdp(device_type=15)),
            rotate_every=1200,
        ),
        _device(
            "mouse", "Swift Pair mouse", "D8:3A:DD:11:02:44", False, 0.9, -59,
            lambda d, t: payload(flags(0x06), microsoft_swift_pair("Surface Mouse")),
            present_until=300,
        ),
        _device(
            "beacon", "Shop beacon", "F1:22:9A:00:11:02", False, 0.1, -81,
            lambda d, t: payload(flags(0x06), ibeacon(major=41, minor=7)),
        ),
        _device(
            "eddy", "Eddystone signage", "E0:4C:12:56:78:90", False, 0.25, -84,
            lambda d, t: (
                eddystone_url() if int(t) % 6 < 4 else eddystone_tlm(adv_count=d._counter,
                                                                     uptime_s=t + 800_000)
            ),
        ),
        _device(
            "buds", "Pixel Buds (pairing)", "5A:CD:33:71:66:12", True, 0.4, -52,
            lambda d, t: fast_pair_discoverable(),
            present_from=120, present_until=200,
        ),
        _device(
            "shelly", "BTHome sensor", "B0:B2:1C:04:9F:31", False, 3.0, -74,
            lambda d, t: bthome(
                temperature=20.5 + 1.5 * math.sin(t / 300),
                humidity=45 + 5 * math.sin(t / 500),
                battery=93,
                packet_id=d._counter % 256,
                motion=(int(t) % 90 < 6),
            ),
        ),
        _device(
            "ruuvi", "RuuviTag", "CB:B8:33:4C:88:4F", True, 1.28, -69,
            lambda d, t: ruuvi(
                temperature=19.0 + 2 * math.sin(t / 400), seq=d._counter % 65536,
                moves=66 + int(t // 600),
            ),
        ),
        _device(
            "govee", "Govee hygrometer", "A4:C1:38:9E:22:10", False, 2.5, -87,
            lambda d, t: payload(flags(0x06), complete_name("GVH5075_2210"), govee()),
        ),
        _device(
            "xiaomi", "Xiaomi thermometer", "A4:C1:38:11:22:33", False, 4.0, -80,
            lambda d, t: xiaomi_thermometer(
                temperature=21.0 + math.sin(t / 350), packet_id=d._counter % 256
            ),
        ),
        _device(
            "hrm", "Heart-rate strap", "D1:5C:99:04:73:20", False, 1.0, -61,
            lambda d, t: heart_rate(bpm=68 + int(8 * abs(math.sin(t / 40)))),
            present_from=60,
        ),
        _device(
            "keyboard", "Bluetooth keyboard", "F4:03:2A:8B:11:60", False, 2.0, -57,
            lambda d, t: keyboard(),
        ),
        _device(
            "exposure", "Phone (Exposure Notification)", "4D:70:1E:B2:9C:05", True, 3.5, -76,
            lambda d, t: exposure_notification(),
            rotate_every=600,
        ),
        _device(
            "smarttag", "Samsung SmartTag", "68:2E:11:D4:05:C3", True, 2.0, -83,
            lambda d, t: samsung_smarttag(),
            rotate_every=900,
        ),
        _device(
            "mystery", "Unknown vendor device", "00:1A:7D:DA:71:13", False, 1.7, -70,
            lambda d, t: payload(flags(0x06), unknown_vendor(counter=d._counter)),
        ),
        _device(
            "passerby", "Passing phone", "7C:2E:DD:31:90:41", True, 0.8, -91,
            lambda d, t: payload(flags(0x1A), apple_nearby_info(action=0x0B)),
            present_from=200, present_until=260, drift=12,
        ),
    ]


def advertisement_from(device: SyntheticDevice, t: float, rng: random.Random,
                       source: str = "synthetic") -> Advertisement:
    device.rotate_if_due(t, rng)
    raw = device.build(t)
    addr_type = (
        classify_address(device.address, device.random_address)
        if device.random_address
        else AddressType.PUBLIC
    )
    return Advertisement(
        address=device.address,
        timestamp=t,
        rssi=device.next_rssi(rng),
        address_type=addr_type,
        raw=raw,
        channel=rng.choice((37, 38, 39)),
        pdu_type=PduType.ADV_IND,
        source=source,
    )
