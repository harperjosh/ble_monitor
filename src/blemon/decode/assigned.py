"""Bluetooth SIG assigned-number lookups, vendored locally.

The tables under ``blemon/data`` are snapshots of the public SIG allocations.
They are loaded lazily from disk and never fetched at runtime — the tool makes
no network requests, ever.
"""

from __future__ import annotations

import functools
import json
from importlib import resources

BLUETOOTH_BASE_SUFFIX = "-0000-1000-8000-00805F9B34FB"


@functools.cache
def _load(name: str) -> dict[str, str]:
    with resources.files("blemon.data").joinpath(name).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def company_name(company_id: int) -> str | None:
    """Resolve a 16-bit Company Identifier to its registered name."""
    return _load("company_ids.json").get(str(company_id))


#: 16-bit UUIDs whose registered owner is less informative than what the UUID
#: is actually used for in the wild. The registry name is still shown as the
#: owner; these are what we lead with.
WELL_KNOWN_UUID16: dict[str, str] = {
    "FEAA": "Eddystone (Google beacon format)",
    "FE2C": "Google Fast Pair",
    "FD6F": "Exposure Notification (Apple/Google contact tracing)",
    "FEED": "Tile tracker",
    "FEEC": "Tile tracker",
    "FD5A": "Samsung SmartThings / SmartTag",
    "FD59": "Samsung",
    "FD44": "Apple (Nearby / AirDrop)",
    "FD43": "Apple (Nearby)",
    "FE9F": "Google",
    "FE8F": "Apple",
    "FDF0": "Google",
    "FE03": "Amazon",
    "FE9E": "Dialog Semiconductor / Chipolo",
    "FEA0": "Google",
    "FDCD": "Xiaomi / Qingping",
    "FE95": "Xiaomi",
    "181C": "User Data",
    "FCF1": "Google",
    "FD3D": "Wyze / Sonos",
    "FE59": "Nordic DFU (device firmware update)",
    "FE61": "Logitech",
    "1812": "Human Interface Device (HID over GATT)",
    "180F": "Battery Service",
    "180D": "Heart Rate",
    "181A": "Environmental Sensing",
    "1809": "Health Thermometer",
    "1808": "Glucose",
    "1810": "Blood Pressure",
    "1816": "Cycling Speed and Cadence",
    "1818": "Cycling Power",
    "1814": "Running Speed and Cadence",
    "FE79": "Zebra",
    "FE26": "Google",
    "FE0F": "Philips Hue",
    "FDA0": "Meta / Facebook",
    "FE9A": "Estimote",
    "FE6F": "LINE",
    "FCD2": "Allterco / Shelly",
    "FE0D": "Procter & Gamble",
    "FE55": "Google (Chromecast setup)",
}


def normalize_uuid(uuid: str) -> str:
    """Upper-case a UUID and collapse the Bluetooth base range to 16/32 bits.

    Both forms of the base range collapse: the full 128-bit dashed form and the
    bare 8-hex 32-bit form. The latter is what the 32-bit Service Data AD type
    (0x20) produces — e.g. "0000FEAA" — and it has to fold to "FEAA" so it
    matches decoders and names registered under the 16-bit key.
    """
    u = uuid.upper().strip()
    if len(u) == 36 and u.endswith(BLUETOOTH_BASE_SUFFIX):
        head = u[:8]
        return head[4:] if head.startswith("0000") else head
    if len(u) == 8 and u.startswith("0000"):
        return u[4:]
    return u


def service_name(uuid: str) -> str | None:
    """Best available name for a service UUID, short or long form."""
    u = normalize_uuid(uuid)
    if u in WELL_KNOWN_UUID16:
        return WELL_KNOWN_UUID16[u]
    gss = _load("service_uuids.json")
    if u in gss:
        return gss[u]
    member = _load("member_uuids.json")
    if u in member:
        return member[u]
    return None


def service_owner(uuid: str) -> str | None:
    """The organisation the UUID is registered to, when it is a member UUID."""
    return _load("member_uuids.json").get(normalize_uuid(uuid))


def characteristic_name(uuid: str) -> str | None:
    return _load("characteristic_uuids.json").get(normalize_uuid(uuid))


# ---------------------------------------------------------------------------
# GAP Appearance
# ---------------------------------------------------------------------------

APPEARANCE_CATEGORIES: dict[int, str] = {
    0: "Unknown",
    1: "Phone",
    2: "Computer",
    3: "Watch",
    4: "Clock",
    5: "Display",
    6: "Remote Control",
    7: "Eye-glasses",
    8: "Tag",
    9: "Keyring",
    10: "Media Player",
    11: "Barcode Scanner",
    12: "Thermometer",
    13: "Heart Rate Sensor",
    14: "Blood Pressure",
    15: "Human Interface Device",
    16: "Glucose Meter",
    17: "Running Walking Sensor",
    18: "Cycling",
    19: "Control Device",
    20: "Network Device",
    21: "Sensor",
    22: "Light Fixtures",
    23: "Fan",
    24: "HVAC",
    25: "Air Conditioning",
    26: "Humidifier",
    27: "Heating",
    28: "Access Control",
    29: "Motorized Device",
    30: "Power Device",
    31: "Light Source",
    32: "Window Covering",
    33: "Audio Sink",
    34: "Audio Source",
    35: "Motorized Vehicle",
    36: "Domestic Appliance",
    37: "Wearable Audio Device",
    38: "Aircraft",
    39: "AV Equipment",
    40: "Display Equipment",
    41: "Hearing Aid",
    42: "Gaming",
    43: "Signage",
    49: "Pulse Oximeter",
    50: "Weight Scale",
    51: "Personal Mobility Device",
    52: "Continuous Glucose Monitor",
    53: "Insulin Pump",
    54: "Medication Delivery",
    55: "Spirometer",
    81: "Outdoor Sports Activity",
}

APPEARANCE_SUBCATEGORIES: dict[tuple[int, int], str] = {
    (1, 1): "Bar Phone",
    (2, 1): "Desktop Workstation",
    (2, 2): "Server-class Computer",
    (2, 3): "Laptop",
    (2, 4): "Handheld PC/PDA",
    (2, 5): "Palm-size PC/PDA",
    (2, 6): "Wearable Computer",
    (2, 7): "Tablet",
    (2, 8): "Docking Station",
    (2, 9): "All-in-One",
    (2, 10): "Blade Server",
    (2, 11): "Convertible",
    (2, 12): "Detachable",
    (2, 13): "IoT Gateway",
    (2, 14): "Mini PC",
    (2, 15): "Stick PC",
    (3, 1): "Sports Watch",
    (3, 2): "Smartwatch",
    (7, 1): "Sunglasses",
    (7, 2): "Reading Glasses",
    (8, 1): "RFID Tag",
    (12, 1): "Ear Thermometer",
    (13, 1): "Heart Rate Belt",
    (14, 1): "Arm Blood Pressure",
    (14, 2): "Wrist Blood Pressure",
    (15, 1): "Keyboard",
    (15, 2): "Mouse",
    (15, 3): "Joystick",
    (15, 4): "Gamepad",
    (15, 5): "Digitizer Tablet",
    (15, 6): "Card Reader",
    (15, 7): "Digital Pen",
    (15, 8): "Barcode Scanner",
    (15, 9): "Touchpad",
    (15, 10): "Presentation Remote",
    (18, 1): "Cycling Computer",
    (18, 2): "Speed Sensor",
    (18, 3): "Cadence Sensor",
    (18, 4): "Power Sensor",
    (18, 5): "Speed and Cadence Sensor",
    (33, 1): "Standalone Speaker",
    (33, 2): "Soundbar",
    (33, 3): "Bookshelf Speaker",
    (33, 4): "Standmounted Speaker",
    (33, 5): "Speakerphone",
    (34, 1): "Microphone",
    (34, 2): "Alarm",
    (34, 3): "Bell",
    (34, 4): "Horn",
    (34, 5): "Broadcasting Device",
    (34, 6): "Service Desk",
    (34, 7): "Kiosk",
    (34, 8): "Broadcasting Room",
    (34, 9): "Auditorium",
    (37, 1): "Earbud",
    (37, 2): "Headset",
    (37, 3): "Headphones",
    (37, 4): "Neck Band",
    (42, 1): "Home Video Game Console",
    (42, 2): "Portable Handheld Console",
    (51, 1): "Wheelchair",
    (51, 2): "Mobility Scooter",
}


def appearance_name(value: int) -> str:
    """Human-readable GAP appearance, e.g. 0x0941 -> 'Wearable Audio Device / Earbud'."""
    category = value >> 6
    sub = value & 0x3F
    cat_name = APPEARANCE_CATEGORIES.get(category, f"Category {category}")
    sub_name = APPEARANCE_SUBCATEGORIES.get((category, sub))
    if sub_name:
        return f"{cat_name} / {sub_name}"
    if sub:
        return f"{cat_name} (subtype {sub})"
    return cat_name
