"""Sensor and health payloads: standard GATT service data plus the common
open and vendor sensor formats that actually saturate the air in practice.

Covered here:

* Standard SIG service data — Battery, Heart Rate, Health Thermometer,
  Environmental Sensing, Exposure Notification.
* BTHome v1/v2 (0xFCD2) — the open format used by Shelly and most DIY sensors.
* Xiaomi MiBeacon (0xFE95) — thermometers, plant sensors, door sensors.
* Ruuvi (company 0x0499) — the reference open environmental tag.
* Govee (company 0xEC88) — very common cheap hygrometers.

These are the payloads where a stranger's device is literally telling you the
temperature of the room it is in, so they matter for the "what are these things
chattering about" question.
"""

from __future__ import annotations

import struct
from typing import Any

from blemon.decode.registry import manufacturer_decoder, service_data_decoder
from blemon.models import Category, Decoding, Field_

# ---------------------------------------------------------------------------
# Standard SIG service data
# ---------------------------------------------------------------------------


@service_data_decoder("180F", name="battery_service")
def decode_battery(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    if not data:
        return []
    pct = data[0]
    return [
        Decoding(
            protocol="gatt_battery",
            summary=f"Battery level {pct}%",
            fields=[Field_("battery_percent", pct, 0, 1)],
            english=(
                f"This device is broadcasting its battery level ({pct}%) without anyone "
                "having to connect to it. Battery percentage drifts slowly and predictably, "
                "which makes it a useful fingerprint for recognising the same device again "
                "after its address rotates."
            ),
            tags=["battery_leak", "plaintext_state"],
        )
    ]


@service_data_decoder("180D", name="heart_rate_service")
def decode_heart_rate(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    if len(data) < 2:
        return []
    flags = data[0]
    wide = bool(flags & 0x01)
    if wide and len(data) >= 3:
        bpm = struct.unpack("<H", data[1:3])[0]
        consumed = 3
    else:
        bpm = data[1]
        consumed = 2
    fields = [
        Field_("flags", f"0x{flags:02X}", 0, 1, "bit 0 selects 8- or 16-bit measurement"),
        Field_("heart_rate_bpm", bpm, 1, consumed - 1),
    ]
    contact = None
    if flags & 0x04:
        contact = bool(flags & 0x02)
        fields.append(Field_("sensor_contact", contact, 0, 1))
    return [
        Decoding(
            protocol="gatt_heart_rate",
            summary=f"Heart rate {bpm} bpm",
            fields=fields,
            english=(
                f"A heart-rate monitor is broadcasting a live measurement of {bpm} beats per "
                "minute, unencrypted, to anyone in range. Most fitness straps only expose "
                "this over an authenticated connection; a device putting it in an "
                "advertisement is publishing somebody's pulse to the room."
            ),
            category=Category.WEARABLE,
            tags=["health_data", "plaintext_content", "sensitive"],
        )
    ]


@service_data_decoder("1809", name="health_thermometer")
def decode_thermometer(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    if len(data) < 5:
        return []
    mantissa = int.from_bytes(data[1:4], "little", signed=True)
    exponent = struct.unpack("<b", data[4:5])[0]
    temp = mantissa * (10.0**exponent)
    unit = "°F" if data[0] & 0x01 else "°C"
    return [
        Decoding(
            protocol="gatt_health_thermometer",
            summary=f"Temperature {temp:.2f}{unit}",
            fields=[
                Field_("flags", f"0x{data[0]:02X}", 0, 1),
                Field_("temperature", round(temp, 2), 1, 4, f"IEEE-11073 float, {unit}"),
            ],
            english=(
                f"A medical thermometer reporting {temp:.2f}{unit} in the clear. If this is a "
                "body thermometer rather than a room one, that is health data being broadcast "
                "without encryption."
            ),
            category=Category.MEDICAL,
            tags=["health_data", "plaintext_content", "sensitive"],
        )
    ]


def _echoes_address(data: bytes, context: dict[str, Any], reverse: bool) -> bool:
    """Whether ``data`` starts with the advertiser's own address in this order."""
    address = str(context.get("address") or "")
    if len(data) < 6 or address.count(":") != 5:
        return False
    try:
        raw = bytes(int(part, 16) for part in address.split(":"))
    except ValueError:
        return False
    return data[:6] == (raw[::-1] if reverse else raw)


@service_data_decoder("181A", name="environmental_sensing")
def decode_environmental(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    # Two incompatible layouts share 0x181A. Assuming either one renders the
    # other's MAC byte-reversed and its readings wrong, while looking perfectly
    # plausible — so they have to be told apart:
    #
    # * pvvx "custom" (15 bytes, Xiaomi LYWSD03MMC and clones on pvvx firmware):
    #   MAC[6] little-endian, temp int16 LE x0.01C, humidity uint16 LE x0.01%,
    #   battery_mv uint16 LE, battery_level uint8, counter, flags. Battery
    #   percent is at byte 12 — 10-11 are millivolts.
    # * ATC1441 (13 bytes): MAC[6] big-endian, temp int16 BE x0.1C, humidity
    #   uint8 %, battery_level uint8, battery_mv uint16 BE, counter.
    #
    # Both echo the sensor's own address, so matching those six bytes against
    # the advertiser's address settles the byte order outright. Length only
    # decides it when the address is unknown or does not match.
    fields: list[Field_] = []
    parts: list[str] = []
    if _echoes_address(data, context, reverse=True):
        is_atc = False
    elif _echoes_address(data, context, reverse=False):
        is_atc = True
    else:
        is_atc = len(data) == 13
    if is_atc and len(data) >= 12:
        addr = ":".join(f"{b:02X}" for b in data[0:6])
        temp = struct.unpack(">h", data[6:8])[0] / 10.0
        fields += [
            Field_("device_address", addr, 0, 6, "echoed inside the payload (big-endian)"),
            Field_("temperature_c", round(temp, 2), 6, 2),
            Field_("humidity_percent", data[8], 8, 1),
            Field_("battery_percent", data[9], 9, 1),
            Field_("battery_mv", struct.unpack(">H", data[10:12])[0], 10, 2),
            Field_("layout", "ATC1441", 0, 0),
        ]
        parts += [f"{temp:.1f} °C", f"{data[8]}% humidity", f"{data[9]}% battery"]
    elif len(data) >= 10:
        addr = ":".join(f"{b:02X}" for b in data[5::-1])
        temp = struct.unpack("<h", data[6:8])[0] / 100.0
        hum = struct.unpack("<H", data[8:10])[0] / 100.0
        fields += [
            Field_("device_address", addr, 0, 6, "echoed inside the payload (little-endian)"),
            Field_("temperature_c", round(temp, 2), 6, 2),
            Field_("humidity_percent", round(hum, 2), 8, 2),
            Field_("layout", "pvvx", 0, 0),
        ]
        parts += [f"{temp:.1f} °C", f"{hum:.0f}% humidity"]
        if len(data) >= 12:
            mv = struct.unpack("<H", data[10:12])[0]
            fields.append(Field_("battery_mv", mv, 10, 2))
        if len(data) >= 13:
            fields.append(Field_("battery_percent", data[12], 12, 1))
            parts.append(f"{data[12]}% battery")
    else:
        fields.append(Field_("payload", data.hex(), 0, len(data)))
    return [
        Decoding(
            protocol="environmental_sensing",
            summary="Environmental sensing: " + (", ".join(parts) or f"{len(data)} bytes"),
            fields=fields,
            english=(
                "An environmental sensor broadcasting its readings openly"
                + (f": {', '.join(parts)}. " if parts else ". ")
                + "This is the benign end of the spectrum — it is telling you about the room, "
                "not about a person. Some of these also echo their own MAC address inside the "
                "payload, which defeats any address rotation the radio is doing."
            ),
            category=Category.SENSOR,
            tags=["sensor", "plaintext_content"],
        )
    ]


@service_data_decoder("FD6F", name="exposure_notification")
def decode_exposure_notification(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    rpi = data[:16].hex().upper() if len(data) >= 16 else data.hex().upper()
    return [
        Decoding(
            protocol="exposure_notification",
            summary=f"Exposure Notification RPI {rpi[:12]}…",
            fields=[
                Field_("rolling_proximity_identifier", rpi, 0, 16, "rotates every 10-20 minutes"),
                Field_("encrypted_metadata", data[16:].hex().upper(), 16, max(0, len(data) - 16)),
            ],
            english=(
                "An Apple/Google Exposure Notification broadcast — the contact-tracing "
                "framework built into iOS and Android. The identifier rotates every 10 to 20 "
                "minutes and carries no account information, so it is deliberately designed "
                "not to be trackable. Seeing one means the framework is enabled on a phone "
                "near you."
            ),
            category=Category.PHONE,
            tags=["exposure_notification", "rotating_identity", "privacy_preserving"],
        )
    ]


# ---------------------------------------------------------------------------
# BTHome (0xFCD2) — the open sensor format
# ---------------------------------------------------------------------------

#: object id -> (name, byte width, signed, scale, unit)
BTHOME_OBJECTS: dict[int, tuple[str, int, bool, float, str]] = {
    0x00: ("packet_id", 1, False, 1, ""),
    0x01: ("battery", 1, False, 1, "%"),
    0x02: ("temperature", 2, True, 0.01, "°C"),
    0x03: ("humidity", 2, False, 0.01, "%"),
    0x04: ("pressure", 3, False, 0.01, "hPa"),
    0x05: ("illuminance", 3, False, 0.01, "lux"),
    0x06: ("mass", 2, False, 0.01, "kg"),
    0x08: ("dewpoint", 2, True, 0.01, "°C"),
    0x09: ("count", 1, False, 1, ""),
    0x0A: ("energy", 3, False, 0.001, "kWh"),
    0x0B: ("power", 3, False, 0.01, "W"),
    0x0C: ("voltage", 2, False, 0.001, "V"),
    0x0D: ("pm2_5", 2, False, 1, "µg/m³"),
    0x0E: ("pm10", 2, False, 1, "µg/m³"),
    0x12: ("co2", 2, False, 1, "ppm"),
    0x13: ("tvoc", 2, False, 1, "µg/m³"),
    0x14: ("moisture", 2, False, 0.01, "%"),
    0x2E: ("humidity", 1, False, 1, "%"),
    0x2F: ("moisture", 1, False, 1, "%"),
    0x3D: ("count", 2, False, 1, ""),
    0x3E: ("count", 4, False, 1, ""),
    0x3F: ("rotation", 2, True, 0.1, "°"),
    0x40: ("distance", 2, False, 1, "mm"),
    0x41: ("distance", 2, False, 0.1, "m"),
    0x42: ("duration", 3, False, 0.001, "s"),
    0x43: ("current", 2, False, 0.001, "A"),
    0x44: ("speed", 2, False, 0.01, "m/s"),
    0x45: ("temperature", 2, True, 0.1, "°C"),
    0x46: ("uv_index", 1, False, 0.1, ""),
    0x47: ("volume", 2, False, 0.1, "L"),
    0x51: ("acceleration", 2, False, 0.001, "m/s²"),
    0x52: ("gyroscope", 2, False, 0.001, "°/s"),
}

#: Binary sensors: object id -> (name, off-label, on-label)
BTHOME_BINARY: dict[int, tuple[str, str, str]] = {
    0x0F: ("generic", "off", "on"),
    0x10: ("power", "off", "on"),
    0x11: ("opening", "closed", "open"),
    0x15: ("battery_low", "normal", "low"),
    0x16: ("battery_charging", "not charging", "charging"),
    0x17: ("carbon_monoxide", "clear", "detected"),
    0x18: ("cold", "normal", "cold"),
    0x19: ("connectivity", "disconnected", "connected"),
    0x1A: ("door", "closed", "open"),
    0x1B: ("garage_door", "closed", "open"),
    0x1C: ("gas", "clear", "detected"),
    0x1D: ("heat", "normal", "hot"),
    0x1E: ("light", "dark", "light"),
    0x1F: ("lock", "locked", "unlocked"),
    0x20: ("moisture", "dry", "wet"),
    0x21: ("motion", "clear", "detected"),
    0x22: ("moving", "still", "moving"),
    0x23: ("occupancy", "clear", "detected"),
    0x24: ("plug", "unplugged", "plugged in"),
    0x25: ("presence", "away", "home"),
    0x26: ("problem", "ok", "problem"),
    0x27: ("running", "stopped", "running"),
    0x28: ("safety", "unsafe", "safe"),
    0x29: ("smoke", "clear", "detected"),
    0x2A: ("sound", "clear", "detected"),
    0x2B: ("tamper", "ok", "tampered"),
    0x2C: ("vibration", "clear", "detected"),
    0x2D: ("window", "closed", "open"),
}

#: Sensitive readings — a motion or occupancy sensor is telling the street
#: whether anyone is home.
BTHOME_SENSITIVE = {0x21, 0x23, 0x25, 0x1A, 0x1B, 0x1F, 0x2D, 0x11}


@service_data_decoder("FCD2", name="bthome")
def decode_bthome(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    if not data:
        return []
    info = data[0]
    encrypted = bool(info & 0x01)
    trigger = bool(info & 0x04)
    version = info >> 5

    fields = [
        Field_("bthome_version", version, 0, 1),
        Field_("encrypted", encrypted, 0, 1),
        Field_("trigger_based", trigger, 0, 1, "sends on change rather than on a timer"),
    ]

    if encrypted:
        return [
            Decoding(
                protocol="bthome",
                summary=f"BTHome v{version} (encrypted)",
                fields=fields + [Field_("ciphertext", data[1:].hex(), 1, len(data) - 1)],
                english=(
                    "A BTHome sensor that has encryption turned on. You can tell it is a "
                    "sensor and how often it transmits, but not what it is measuring — which "
                    "is exactly how this should look."
                ),
                category=Category.SENSOR,
                tags=["bthome", "sensor", "encrypted"],
            )
        ]

    readings: list[str] = []
    sensitive = False
    i = 1
    while i < len(data):
        obj = data[i]
        if obj in BTHOME_BINARY:
            if i + 1 >= len(data):
                break
            name, off, on = BTHOME_BINARY[obj]
            state = on if data[i + 1] else off
            fields.append(Field_(name, state, i + 1, 1))
            readings.append(f"{name.replace('_', ' ')}: {state}")
            if obj in BTHOME_SENSITIVE:
                sensitive = True
            i += 2
            continue
        spec = BTHOME_OBJECTS.get(obj)
        if not spec:
            fields.append(Field_(f"unknown_object_0x{obj:02X}", data[i + 1 :].hex(), i + 1, None))
            break
        name, width, signed, scale, unit = spec
        raw = data[i + 1 : i + 1 + width]
        if len(raw) < width:
            break
        value = int.from_bytes(raw, "little", signed=signed) * scale
        value = round(value, 4)
        fields.append(Field_(name, value, i + 1, width, unit or None))
        readings.append(f"{name.replace('_', ' ')} {value}{unit}")
        i += 1 + width

    body = ", ".join(readings) or "no readings decoded"
    return [
        Decoding(
            protocol="bthome",
            summary=f"BTHome v{version}: {body}",
            fields=fields,
            english=(
                f"A BTHome sensor broadcasting in the clear: {body}. BTHome is the open "
                "format used by Shelly devices and most home-built sensors. Encryption is "
                "optional and this one has it switched off, so every reading is public."
                + (
                    " Note that this includes occupancy or opening state — which tells anyone "
                    "listening whether the space is occupied."
                    if sensitive
                    else ""
                )
            ),
            category=Category.SENSOR,
            tags=["bthome", "sensor", "plaintext_content"]
            + (["sensitive", "occupancy_leak"] if sensitive else []),
        )
    ]


# ---------------------------------------------------------------------------
# Xiaomi MiBeacon (0xFE95)
# ---------------------------------------------------------------------------

XIAOMI_EVENTS: dict[int, str] = {
    0x1001: "button",
    0x1002: "sleep",
    0x1003: "rssi",
    0x1004: "temperature",
    0x1005: "power_and_temperature",
    0x1006: "humidity",
    0x1007: "illuminance",
    0x1008: "moisture",
    0x1009: "conductivity",
    0x100A: "battery",
    0x100D: "temperature_and_humidity",
    0x100E: "lock",
    0x100F: "door",
    0x1010: "formaldehyde",
    0x1012: "opening",
    0x1013: "consumable",
    0x1014: "moisture_detected",
    0x1015: "smoke",
    0x1017: "motion_inactivity",
    0x1018: "light_intensity",
    0x1019: "door_sensor",
    0x0003: "motion",
    0x0006: "fingerprint",
    0x0007: "door",
    0x000A: "battery",
    0x000B: "lock",
    0x000F: "motion_with_illuminance",
}

XIAOMI_DEVICES: dict[int, str] = {
    0x01AA: "LYWSDCGQ thermometer",
    0x045B: "LYWSD02 clock thermometer",
    0x055B: "LYWSD03MMC thermometer",
    0x098B: "MCCGQ02HL door/window sensor",
    0x0098: "HHCCJCY01 plant sensor",
    0x03BC: "GCLS002 grow sensor",
    0x0347: "CGG1 thermometer",
    0x0387: "MHO-C401 thermometer",
    0x06D3: "MHO-C303 clock",
    0x02DF: "JQJCY01YM formaldehyde sensor",
    0x0A8D: "RTCGQ02LM motion sensor",
    0x07F6: "MJYD02YL night light",
    0x0153: "WX08ZM mosquito repeller",
    0x04E9: "MCCGQ02HL door sensor",
    0x0863: "SJWS01LM flood sensor",
}


@service_data_decoder("FE95", name="xiaomi_mibeacon")
def decode_xiaomi(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    if len(data) < 5:
        return []
    fctrl = struct.unpack("<H", data[0:2])[0]
    device_type = struct.unpack("<H", data[2:4])[0]
    packet_id = data[4]

    encrypted = bool((fctrl >> 3) & 1)
    mac_included = bool((fctrl >> 4) & 1)
    cap_included = bool((fctrl >> 5) & 1)
    obj_included = bool((fctrl >> 6) & 1)

    device_name = XIAOMI_DEVICES.get(device_type, f"unknown model 0x{device_type:04X}")
    fields = [
        Field_("frame_control", f"0x{fctrl:04X}", 0, 2),
        Field_("device_type", f"0x{device_type:04X}", 2, 2, device_name),
        Field_("packet_id", packet_id, 4, 1, "increments per transmission"),
        Field_("encrypted", encrypted, 0, 2),
    ]

    i = 5
    if mac_included and len(data) >= i + 6:
        addr = ":".join(f"{b:02X}" for b in data[i : i + 6][::-1])
        fields.append(Field_("device_address", addr, i, 6, "echoed inside the payload"))
        i += 6
    if cap_included and len(data) > i:
        fields.append(Field_("capability", f"0x{data[i]:02X}", i, 1))
        i += 1

    readings: list[str] = []
    if obj_included and not encrypted and len(data) >= i + 3:
        etype = struct.unpack("<H", data[i : i + 2])[0]
        elen = data[i + 2]
        ebody = data[i + 3 : i + 3 + elen]
        ename = XIAOMI_EVENTS.get(etype, f"unknown event 0x{etype:04X}")
        value: Any = ebody.hex()
        if ename == "temperature" and len(ebody) >= 2:
            value = struct.unpack("<h", ebody[:2])[0] / 10.0
            readings.append(f"{value} °C")
        elif ename == "humidity" and len(ebody) >= 2:
            value = struct.unpack("<H", ebody[:2])[0] / 10.0
            readings.append(f"{value}% humidity")
        elif ename == "temperature_and_humidity" and len(ebody) >= 4:
            t = struct.unpack("<h", ebody[:2])[0] / 10.0
            h = struct.unpack("<H", ebody[2:4])[0] / 10.0
            value = {"temperature_c": t, "humidity_percent": h}
            readings.append(f"{t} °C and {h}% humidity")
        elif ename == "battery" and ebody:
            value = ebody[0]
            readings.append(f"{value}% battery")
        elif ename == "illuminance" and len(ebody) >= 3:
            value = int.from_bytes(ebody[:3], "little")
            readings.append(f"{value} lux")
        elif ename == "moisture" and ebody:
            value = ebody[0]
            readings.append(f"{value}% soil moisture")
        elif ename == "conductivity" and len(ebody) >= 2:
            value = struct.unpack("<H", ebody[:2])[0]
            readings.append(f"{value} µS/cm soil conductivity")
        elif ename in ("motion", "motion_inactivity", "door", "door_sensor", "opening", "lock"):
            readings.append(f"{ename.replace('_', ' ')} event")
        fields.append(Field_(ename, value, i + 3, elen))

    body = ", ".join(readings)
    return [
        Decoding(
            protocol="xiaomi_mibeacon",
            summary=f"Xiaomi {device_name}" + (f": {body}" if body else ""),
            fields=fields,
            english=(
                f"A Xiaomi/Mijia sensor ({device_name}). "
                + (
                    "Its payload is encrypted with a key bound to the owner's account, so the "
                    "readings are private — but the model number and a per-packet counter are "
                    "still public."
                    if encrypted
                    else (
                        f"It is broadcasting {body} unencrypted, so anyone in range knows it. "
                        if body
                        else "Its readings are unencrypted. "
                    )
                )
                + (
                    "It also echoes its own MAC address inside the payload, which cancels out "
                    "any address privacy the radio layer might have provided."
                    if mac_included
                    else ""
                )
            ),
            category=Category.SENSOR,
            tags=["xiaomi", "sensor"]
            + (["encrypted"] if encrypted else ["plaintext_content"])
            + (["mac_in_payload"] if mac_included else []),
        )
    ]


# ---------------------------------------------------------------------------
# Ruuvi (company 0x0499)
# ---------------------------------------------------------------------------


@manufacturer_decoder(0x0499, name="ruuvi")
def decode_ruuvi(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    if not data:
        return []
    fmt = data[0]
    if fmt != 0x05 or len(data) < 24:
        return [
            Decoding(
                protocol="ruuvi",
                summary=f"RuuviTag data format 0x{fmt:02X}, {len(data)} bytes",
                fields=[Field_("payload", data.hex(), 0, len(data))],
                english="A RuuviTag environmental sensor using a data format we do not "
                "decode in detail.",
                category=Category.SENSOR,
                tags=["ruuvi", "sensor"],
            )
        ]

    temp, hum, pres, ax, ay, az, power, moves, seq = struct.unpack(">hHHhhhHBH", data[1:18])
    addr = ":".join(f"{b:02X}" for b in data[18:24])
    temp_c = temp * 0.005
    hum_pct = hum * 0.0025
    pres_hpa = (pres + 50000) / 100.0
    voltage = ((power >> 5) + 1600) / 1000.0
    tx_dbm = (power & 0x1F) * 2 - 40

    return [
        Decoding(
            protocol="ruuvi",
            summary=(
                f"RuuviTag: {temp_c:.2f}°C, {hum_pct:.1f}%RH, {pres_hpa:.1f}hPa, "
                f"{voltage:.3f}V, seq {seq}"
            ),
            fields=[
                Field_("data_format", 5, 0, 1, "RAWv2"),
                Field_("temperature_c", round(temp_c, 3), 1, 2),
                Field_("humidity_percent", round(hum_pct, 3), 3, 2),
                Field_("pressure_hpa", round(pres_hpa, 2), 5, 2),
                Field_("acceleration_mg", {"x": ax, "y": ay, "z": az}, 7, 6),
                Field_("battery_volts", round(voltage, 3), 13, 2),
                Field_("tx_power_dbm", tx_dbm, 13, 2),
                Field_("movement_counter", moves, 15, 1, "increments when the tag is moved"),
                Field_("sequence_number", seq, 16, 2),
                Field_("device_address", addr, 18, 6, "echoed inside the payload"),
            ],
            english=(
                f"A RuuviTag — an open-source environmental sensor — reporting {temp_c:.1f} °C, "
                f"{hum_pct:.0f}% humidity and {pres_hpa:.0f} hPa, plus its own orientation and "
                f"battery voltage. It has been moved {moves} times since power-on. Everything "
                "here is deliberately public: Ruuvi's whole design is that anyone can read it. "
                "It also puts its MAC address in the payload, so it is permanently identifiable."
            ),
            category=Category.SENSOR,
            tags=["ruuvi", "sensor", "plaintext_content", "mac_in_payload", "counter_leak"],
        )
    ]


# ---------------------------------------------------------------------------
# Govee (company 0xEC88)
# ---------------------------------------------------------------------------


@manufacturer_decoder(0xEC88, name="govee")
def decode_govee(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    if len(data) < 5:
        return []
    packed = int.from_bytes(data[1:4], "big")
    negative = bool(packed & 0x800000)
    packed &= 0x7FFFFF
    # Temperature and humidity share one 24-bit integer: value = temp*10000 +
    # hum*10. Temperature must be recovered as (value // 1000) / 10, NOT
    # value / 10000 — dividing by 10000 folds the humidity digits into the
    # temperature and reports it up to 0.1 degree too high whenever humidity is
    # 50% or more (e.g. 21.0C/60% packs to 210600, and 210600/10000 rounds to
    # 21.1). Integer-dividing away the humidity digits first is exact.
    temp_c = round((packed // 1000) / 10.0 * (-1 if negative else 1), 1)
    humidity = round((packed % 1000) / 10.0, 1)
    battery = data[4]
    return [
        Decoding(
            protocol="govee",
            summary=f"Govee sensor: {temp_c:.1f}°C, {humidity:.1f}%RH, battery {battery}%",
            fields=[
                Field_("temperature_c", temp_c, 1, 3, "0.1 resolution; packed with humidity"),
                Field_("humidity_percent", humidity, 1, 3, "packed with temperature"),
                Field_("battery_percent", battery, 4, 1),
            ],
            english=(
                f"A Govee hygrometer — one of the cheap wireless thermometers — broadcasting "
                f"{temp_c:.1f} °C and {humidity:.0f}% humidity in the clear, with "
                f"{battery}% battery. These transmit constantly and have no privacy features "
                "at all, so if there is one in a home nearby you can watch its room's climate."
            ),
            category=Category.SENSOR,
            tags=["govee", "sensor", "plaintext_content", "battery_leak"],
        )
    ]
