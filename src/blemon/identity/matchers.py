"""The bundled matcher library.

Each matcher looks at one kind of signal and returns whatever it can justify
from that signal alone. The engine handles combining them. Matchers must never
over-claim: a company ID tells you who made the radio, not what the product is,
and the confidence returned has to reflect that.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING

from blemon.decode.apple import PROXIMITY_MODELS
from blemon.identity.engine import guess, matcher
from blemon.models import Category, Confidence, Guess

if TYPE_CHECKING:  # pragma: no cover
    from blemon.device import Device


# ---------------------------------------------------------------------------
# 1. GAP appearance — the device telling us what it is, in a standard field
# ---------------------------------------------------------------------------

APPEARANCE_CATEGORY: dict[int, tuple[str, Category]] = {
    1: ("Phone", Category.PHONE),
    2: ("Computer", Category.COMPUTER),
    3: ("Watch", Category.WEARABLE),
    4: ("Clock", Category.APPLIANCE),
    5: ("Display", Category.APPLIANCE),
    6: ("Remote control", Category.PERIPHERAL),
    7: ("Smart glasses", Category.WEARABLE),
    8: ("Tag", Category.TRACKER),
    9: ("Keyring tag", Category.TRACKER),
    10: ("Media player", Category.AUDIO),
    12: ("Thermometer", Category.MEDICAL),
    13: ("Heart-rate sensor", Category.WEARABLE),
    14: ("Blood-pressure monitor", Category.MEDICAL),
    15: ("Input device", Category.PERIPHERAL),
    16: ("Glucose meter", Category.MEDICAL),
    17: ("Running/walking sensor", Category.WEARABLE),
    18: ("Cycling sensor", Category.WEARABLE),
    20: ("Network device", Category.NETWORK),
    21: ("Sensor", Category.SENSOR),
    22: ("Light fitting", Category.APPLIANCE),
    28: ("Access control device", Category.APPLIANCE),
    31: ("Light", Category.APPLIANCE),
    33: ("Speaker", Category.AUDIO),
    34: ("Microphone or audio source", Category.AUDIO),
    35: ("Vehicle", Category.VEHICLE),
    36: ("Domestic appliance", Category.APPLIANCE),
    37: ("Wireless earbuds or headphones", Category.AUDIO),
    39: ("AV equipment", Category.AUDIO),
    41: ("Hearing aid", Category.MEDICAL),
    42: ("Games controller", Category.PERIPHERAL),
    49: ("Pulse oximeter", Category.MEDICAL),
    50: ("Weight scale", Category.APPLIANCE),
    52: ("Continuous glucose monitor", Category.MEDICAL),
    53: ("Insulin pump", Category.MEDICAL),
}


@matcher("appearance")
def by_appearance(device: Device) -> Iterable[Guess]:
    if device.appearance is None:
        return []
    category_code = device.appearance >> 6
    entry = APPEARANCE_CATEGORY.get(category_code)
    if not entry:
        return []
    label, cat = entry
    specific = device.appearance_name or label
    return [
        guess(
            specific.split(" / ")[-1] if " / " in specific else label,
            Confidence.HIGH,
            [
                f"advertises GAP appearance 0x{device.appearance:04X} "
                f"({device.appearance_name}), a standard self-declared device class"
            ],
            cat,
        )
    ]


# ---------------------------------------------------------------------------
# 2. Advertised name
# ---------------------------------------------------------------------------

NAME_RULES: list[tuple[str, str, Category, Confidence, str | None]] = [
    (r"\bairpods?\s*max\b", "AirPods Max", Category.AUDIO, Confidence.HIGH, "Apple"),
    (r"\bairpods?\s*pro\b", "AirPods Pro", Category.AUDIO, Confidence.HIGH, "Apple"),
    (r"\bairpods?\b", "AirPods", Category.AUDIO, Confidence.HIGH, "Apple"),
    (r"\bbeats\b", "Beats headphones", Category.AUDIO, Confidence.HIGH, "Apple"),
    (r"\bapple\s*watch\b", "Apple Watch", Category.WEARABLE, Confidence.HIGH, "Apple"),
    (r"\bmacbook\b", "MacBook", Category.COMPUTER, Confidence.HIGH, "Apple"),
    (r"\bhomepod\b", "HomePod", Category.AUDIO, Confidence.HIGH, "Apple"),
    (r"\bapple\s*tv\b", "Apple TV", Category.APPLIANCE, Confidence.HIGH, "Apple"),
    (r"\bmagic\s*(keyboard|mouse|trackpad)\b", "Apple input device", Category.PERIPHERAL, Confidence.HIGH, "Apple"),
    (r"\bgalaxy\s*buds\b", "Galaxy Buds", Category.AUDIO, Confidence.HIGH, "Samsung"),
    (r"\bgalaxy\s*watch\b", "Galaxy Watch", Category.WEARABLE, Confidence.HIGH, "Samsung"),
    (r"\bgalaxy\b", "Samsung Galaxy device", Category.PHONE, Confidence.MEDIUM, "Samsung"),
    (r"\bsmarttag\b", "Samsung SmartTag", Category.TRACKER, Confidence.HIGH, "Samsung"),
    (r"\bpixel\s*buds\b", "Pixel Buds", Category.AUDIO, Confidence.HIGH, "Google"),
    (r"\bpixel\b", "Google Pixel", Category.PHONE, Confidence.MEDIUM, "Google"),
    (r"\bchromecast\b", "Chromecast", Category.APPLIANCE, Confidence.HIGH, "Google"),
    (r"\bnest\b", "Google Nest device", Category.APPLIANCE, Confidence.MEDIUM, "Google"),
    (r"\bfitbit\b", "Fitbit", Category.WEARABLE, Confidence.HIGH, "Google"),
    (r"\bgarmin\b", "Garmin device", Category.WEARABLE, Confidence.HIGH, "Garmin"),
    (r"\bpolar\b", "Polar sensor", Category.WEARABLE, Confidence.HIGH, "Polar"),
    (r"\bwahoo\b", "Wahoo sensor", Category.WEARABLE, Confidence.HIGH, "Wahoo"),
    (r"\bwhoop\b", "WHOOP band", Category.WEARABLE, Confidence.HIGH, "WHOOP"),
    (r"\boura\b", "Oura Ring", Category.WEARABLE, Confidence.HIGH, "Oura"),
    (r"\btile\b", "Tile tracker", Category.TRACKER, Confidence.HIGH, "Tile"),
    (r"\bchipolo\b", "Chipolo tracker", Category.TRACKER, Confidence.HIGH, "Chipolo"),
    (r"\btesla\b", "Tesla vehicle", Category.VEHICLE, Confidence.HIGH, "Tesla"),
    (r"\bmy\s*bmw|\bbmw\b", "BMW vehicle", Category.VEHICLE, Confidence.MEDIUM, "BMW"),
    (r"\bsonos\b", "Sonos speaker", Category.AUDIO, Confidence.HIGH, "Sonos"),
    (r"\bbose\b", "Bose audio device", Category.AUDIO, Confidence.HIGH, "Bose"),
    (r"\bjbl\b", "JBL speaker", Category.AUDIO, Confidence.HIGH, "JBL"),
    (r"\bsoundcore|anker\b", "Anker/Soundcore audio", Category.AUDIO, Confidence.MEDIUM, "Anker"),
    (r"\bwh-1000|wf-1000\b", "Sony 1000X headphones", Category.AUDIO, Confidence.HIGH, "Sony"),
    (r"\bshelly\b", "Shelly smart relay", Category.APPLIANCE, Confidence.HIGH, "Shelly"),
    (r"\bgovee|gvh\d{4}\b", "Govee sensor", Category.SENSOR, Confidence.HIGH, "Govee"),
    (r"\bruuvi\b", "RuuviTag", Category.SENSOR, Confidence.HIGH, "Ruuvi"),
    (r"\baranet\b", "Aranet CO2 sensor", Category.SENSOR, Confidence.HIGH, "Aranet"),
    (r"\bswitchbot\b", "SwitchBot device", Category.APPLIANCE, Confidence.HIGH, "SwitchBot"),
    (r"\bhue\b", "Philips Hue light", Category.APPLIANCE, Confidence.MEDIUM, "Signify"),
    (r"\blywsd|mho-?c\d|mi\s*(band|scale)\b", "Xiaomi sensor", Category.SENSOR, Confidence.HIGH, "Xiaomi"),
    (r"\bthinkpad|latitude|elitebook\b", "Business laptop", Category.COMPUTER, Confidence.MEDIUM, None),
    (r"\bprinter|officejet|laserjet\b", "Printer", Category.APPLIANCE, Confidence.HIGH, None),
    (r"\btv\b|\bsmart\s*tv\b|\bbravia\b|\bviera\b", "Television", Category.APPLIANCE, Confidence.MEDIUM, None),
    (r"\bhrm|heart\s*rate\b", "Heart-rate monitor", Category.WEARABLE, Confidence.HIGH, None),
    (r"\bscale\b", "Weighing scale", Category.APPLIANCE, Confidence.MEDIUM, None),
    (r"\bthermo|temp\b", "Thermometer", Category.SENSOR, Confidence.MEDIUM, None),
    (r"\bkeyboard\b", "Keyboard", Category.PERIPHERAL, Confidence.HIGH, None),
    (r"\bmouse\b", "Mouse", Category.PERIPHERAL, Confidence.HIGH, None),
    (r"\bcontroller|gamepad|dualsense|xbox\b", "Games controller", Category.PERIPHERAL, Confidence.HIGH, None),
]


@matcher("advertised_name")
def by_name(device: Device) -> Iterable[Guess]:
    out: list[Guess] = []
    for name in device.names:
        lowered = name.lower()
        for pattern, label, cat, conf, vendor in NAME_RULES:
            if re.search(pattern, lowered):
                out.append(
                    guess(
                        label,
                        conf,
                        [f"advertises the name “{name}”, which matches /{pattern}/"],
                        cat,
                        vendor,
                    )
                )
    return out


# ---------------------------------------------------------------------------
# 3. Advertised service UUIDs
# ---------------------------------------------------------------------------

SERVICE_RULES: dict[str, tuple[str, Category, Confidence]] = {
    "1812": ("Input device (keyboard, mouse or controller)", Category.PERIPHERAL, Confidence.HIGH),
    "180D": ("Heart-rate monitor", Category.WEARABLE, Confidence.HIGH),
    "1816": ("Cycling speed/cadence sensor", Category.WEARABLE, Confidence.HIGH),
    "1818": ("Cycling power meter", Category.WEARABLE, Confidence.HIGH),
    "1814": ("Running speed sensor", Category.WEARABLE, Confidence.HIGH),
    "1808": ("Glucose meter", Category.MEDICAL, Confidence.HIGH),
    "1810": ("Blood-pressure monitor", Category.MEDICAL, Confidence.HIGH),
    "1809": ("Thermometer", Category.MEDICAL, Confidence.HIGH),
    "181D": ("Weighing scale", Category.APPLIANCE, Confidence.HIGH),
    "181A": ("Environmental sensor", Category.SENSOR, Confidence.HIGH),
    "1826": ("Fitness machine", Category.APPLIANCE, Confidence.HIGH),
    "FE59": ("Device in firmware-update mode", Category.UNKNOWN, Confidence.MEDIUM),
    "FE9F": ("Google device", Category.UNKNOWN, Confidence.LOW),
    "FE0F": ("Philips Hue light", Category.APPLIANCE, Confidence.MEDIUM),
    "FD3D": ("Sonos or Wyze device", Category.AUDIO, Confidence.LOW),
    "FCD2": ("BTHome sensor", Category.SENSOR, Confidence.HIGH),
    "FE95": ("Xiaomi/Mijia sensor", Category.SENSOR, Confidence.HIGH),
    "FE07": ("Sonos speaker", Category.AUDIO, Confidence.MEDIUM),
    "FD6F": ("Phone with Exposure Notification enabled", Category.PHONE, Confidence.HIGH),
    "FE2C": ("Fast Pair accessory", Category.AUDIO, Confidence.MEDIUM),
    "FEAA": ("Eddystone beacon", Category.BEACON, Confidence.HIGH),
    "FEED": ("Tile tracker", Category.TRACKER, Confidence.HIGH),
    "FD5A": ("Samsung SmartTag", Category.TRACKER, Confidence.HIGH),
}


@matcher("service_uuid")
def by_service(device: Device) -> Iterable[Guess]:
    out: list[Guess] = []
    for uuid, name in zip(device.service_uuids, device.service_names, strict=True):
        rule = SERVICE_RULES.get(uuid.upper())
        if not rule:
            continue
        label, cat, conf = rule
        detail = f" ({name})" if name else ""
        out.append(
            guess(label, conf, [f"advertises service UUID {uuid}{detail}"], cat)
        )
    return out


# ---------------------------------------------------------------------------
# 4. Decoded protocols — the strongest signal we have
# ---------------------------------------------------------------------------


@matcher("decoded_protocol")
def by_protocol(device: Device) -> Iterable[Guess]:
    out: list[Guess] = []
    p = device.protocols

    if "apple_proximity_pairing" in p:
        model_label = _airpods_model(device)
        out.append(
            guess(
                model_label or "Apple wireless earbuds",
                Confidence.HIGH if model_label else Confidence.MEDIUM,
                [
                    "broadcasts an Apple Proximity Pairing message, which only AirPods and "
                    "Beats products send"
                ]
                + ([f"the model field decodes to “{model_label}”"] if model_label else []),
                Category.AUDIO,
                "Apple",
            )
        )
    if "apple_find_my" in p:
        out.append(
            guess(
                "AirTag or Find My accessory",
                Confidence.HIGH,
                [
                    "broadcasts Apple Find My offline-finding advertisements",
                    "carries a rotating P-224 public key in the payload",
                ],
                Category.TRACKER,
                "Apple",
            )
        )
    if "apple_nearby_info" in p:
        out.append(
            guess(
                "Apple device (iPhone, iPad or Mac)",
                Confidence.HIGH,
                [
                    "broadcasts Apple Continuity Nearby Info, which every signed-in "
                    "Apple device emits continuously"
                ],
                Category.PHONE,
                "Apple",
            )
        )
    if "apple_magic_switch" in p:
        out.append(
            guess(
                "Apple Watch",
                Confidence.HIGH,
                ["broadcasts Magic Switch wrist-detection messages, which only the Watch sends"],
                Category.WEARABLE,
                "Apple",
            )
        )
    if "apple_tethering_source" in p:
        out.append(
            guess(
                "iPhone (Personal Hotspot on)",
                Confidence.HIGH,
                ["advertises a Personal Hotspot, which only an iPhone or cellular iPad does"],
                Category.PHONE,
                "Apple",
            )
        )
    if "apple_homekit" in p:
        out.append(
            guess(
                "HomeKit accessory",
                Confidence.HIGH,
                ["broadcasts a HomeKit accessory advertisement"],
                Category.APPLIANCE,
                "Apple",
            )
        )
    if "apple_airplay_target" in p:
        out.append(
            guess(
                "Apple TV or AirPlay speaker",
                Confidence.HIGH,
                ["advertises itself as an AirPlay target"],
                Category.APPLIANCE,
                "Apple",
            )
        )
    if "ibeacon" in p:
        out.append(
            guess(
                "iBeacon transmitter",
                Confidence.HIGH,
                ["broadcasts a well-formed iBeacon frame with a fixed UUID/major/minor"],
                Category.BEACON,
            )
        )
    if any(k.startswith("eddystone") for k in p):
        out.append(
            guess(
                "Eddystone beacon",
                Confidence.HIGH,
                ["broadcasts Eddystone frames on service UUID 0xFEAA"],
                Category.BEACON,
            )
        )
    if "google_find_my_device" in p:
        out.append(
            guess(
                "Google Find My Device tag",
                Confidence.HIGH,
                ["broadcasts a Find My Device Network beacon frame"],
                Category.TRACKER,
                "Google",
            )
        )
    if "fast_pair" in p:
        out.append(
            guess(
                "Fast Pair accessory",
                Confidence.MEDIUM,
                ["broadcasts Google Fast Pair service data"],
                Category.AUDIO,
                "Google",
            )
        )
    if "microsoft_cdp" in p:
        label = _cdp_label(device)
        out.append(
            guess(
                label,
                Confidence.HIGH,
                [
                    "broadcasts a Microsoft Connected Devices beacon, whose device-type "
                    "field is not encrypted"
                ],
                _cdp_category(device),
                "Microsoft",
            )
        )
    if "microsoft_swift_pair" in p:
        out.append(
            guess(
                "Swift Pair accessory in pairing mode",
                Confidence.HIGH,
                ["broadcasts a Microsoft Swift Pair advertisement"],
                Category.PERIPHERAL,
                "Microsoft",
            )
        )
    if "tile" in p:
        out.append(guess("Tile tracker", Confidence.HIGH, ["broadcasts Tile service data"], Category.TRACKER, "Tile"))
    if "samsung_smarttag" in p or "samsung_offline_finding" in p:
        out.append(
            guess(
                "Samsung SmartTag",
                Confidence.HIGH,
                ["broadcasts Samsung SmartThings Find service data"],
                Category.TRACKER,
                "Samsung",
            )
        )
    if "exposure_notification" in p:
        out.append(
            guess(
                "Phone with Exposure Notification enabled",
                Confidence.HIGH,
                ["broadcasts Exposure Notification rolling proximity identifiers"],
                Category.PHONE,
            )
        )
    if "bthome" in p:
        out.append(guess("BTHome sensor", Confidence.HIGH, ["broadcasts BTHome service data"], Category.SENSOR))
    if "xiaomi_mibeacon" in p:
        out.append(
            guess(
                _xiaomi_label(device),
                Confidence.HIGH,
                ["broadcasts a Xiaomi MiBeacon frame with a recognised device-type field"],
                Category.SENSOR,
                "Xiaomi",
            )
        )
    if "ruuvi" in p:
        out.append(guess("RuuviTag", Confidence.HIGH, ["broadcasts Ruuvi RAWv2 manufacturer data"], Category.SENSOR, "Ruuvi"))
    if "govee" in p:
        out.append(guess("Govee sensor", Confidence.HIGH, ["broadcasts Govee manufacturer data"], Category.SENSOR, "Govee"))
    if "gatt_heart_rate" in p:
        out.append(
            guess(
                "Heart-rate monitor",
                Confidence.HIGH,
                ["publishes a live heart-rate measurement in its advertisement"],
                Category.WEARABLE,
            )
        )
    return out


def _airpods_model(device: Device) -> str | None:
    parsed = device.last_parsed
    if not parsed:
        return None
    for d in parsed.decodings:
        if d.protocol != "apple_proximity_pairing":
            continue
        for f in d.fields:
            if f.name == "model" and f.note and not f.note.startswith("unrecognised"):
                return f.note
    return None


def _cdp_label(device: Device) -> str:
    parsed = device.last_parsed
    if parsed:
        for d in parsed.decodings:
            if d.protocol == "microsoft_cdp":
                for f in d.fields:
                    if f.name == "device_type" and f.note:
                        return f.note.capitalize()
    return "Windows or Xbox device"


def _cdp_category(device: Device) -> Category:
    parsed = device.last_parsed
    if parsed:
        for d in parsed.decodings:
            if d.protocol == "microsoft_cdp" and d.category:
                return d.category
    return Category.COMPUTER


def _xiaomi_label(device: Device) -> str:
    parsed = device.last_parsed
    if parsed:
        for d in parsed.decodings:
            if d.protocol == "xiaomi_mibeacon":
                for f in d.fields:
                    if f.name == "device_type" and f.note and not f.note.startswith("unknown"):
                        return f"Xiaomi {f.note}"
    return "Xiaomi sensor"


# ---------------------------------------------------------------------------
# 5. Company ID — who made the radio, not what the product is
# ---------------------------------------------------------------------------

VENDOR_CATEGORY_HINTS: dict[int, tuple[str, Category]] = {
    0x004C: ("Apple device", Category.PHONE),
    0x0006: ("Microsoft device", Category.COMPUTER),
    0x0075: ("Samsung device", Category.PHONE),
    0x00E0: ("Google device", Category.PHONE),
    0x0087: ("Garmin device", Category.WEARABLE),
    0x0157: ("Tile tracker", Category.TRACKER),
    0x0499: ("RuuviTag", Category.SENSOR),
    0x038F: ("Xiaomi device", Category.SENSOR),
    0x02E5: ("Espressif (ESP32) device", Category.SENSOR),
    0x0059: ("Nordic Semiconductor device", Category.SENSOR),
    0x0171: ("Amazon device", Category.APPLIANCE),
    0x0180: ("Fitbit", Category.WEARABLE),
    0x01D1: ("GoPro", Category.PERIPHERAL),
    0x0154: ("Bose", Category.AUDIO),
    0x012D: ("Sony", Category.AUDIO),
    0x0085: ("BlueRadios module", Category.UNKNOWN),
    0x0117: ("Sonos", Category.AUDIO),
}


@matcher("company_id")
def by_company(device: Device) -> Iterable[Guess]:
    out: list[Guess] = []
    for cid, name in zip(device.company_ids, device.company_names, strict=True):
        hint = VENDOR_CATEGORY_HINTS.get(cid)
        if hint:
            label, cat = hint
            out.append(
                guess(
                    label,
                    Confidence.LOW,
                    [
                        f"uses Bluetooth company ID 0x{cid:04X}, registered to {name}. "
                        "That identifies the maker, not the product."
                    ],
                    cat,
                    name,
                )
            )
        else:
            out.append(
                guess(
                    f"{name} device",
                    Confidence.LOW,
                    [
                        f"uses Bluetooth company ID 0x{cid:04X}, registered to {name}. "
                        "We know who made it and nothing more."
                    ],
                    Category.UNKNOWN,
                    name,
                )
            )
    return out


# ---------------------------------------------------------------------------
# 6. Behaviour — how it transmits, when we know nothing else
# ---------------------------------------------------------------------------


@matcher("behaviour")
def by_behaviour(device: Device) -> Iterable[Guess]:
    # Only speak up when the stronger matchers have nothing, so we do not
    # clutter the runners-up list on every well-identified device.
    if device.protocols or device.names or device.appearance is not None:
        return []
    if device.packet_count < 5:
        return []

    rate = device.advertising_rate
    evidence = [
        f"advertises about {rate:.1f} times per second",
        f"address type is {device.address_type.value.replace('_', ' ')}",
    ]
    if device.tx_power is not None:
        evidence.append(f"declares TX power {device.tx_power} dBm")

    if rate > 5 and device.address_type.is_rotating:
        return [
            guess(
                "Phone or tablet",
                Confidence.LOW,
                evidence
                + [
                    "a high advertising rate combined with a rotating address is "
                    "characteristic of a modern phone"
                ],
                Category.PHONE,
            )
        ]
    if rate < 0.5 and device.address_type.is_stable:
        return [
            guess(
                "Battery-powered sensor or tag",
                Confidence.LOW,
                evidence
                + [
                    "a slow, regular advertising rate on a fixed address is how "
                    "battery-conscious sensors behave"
                ],
                Category.SENSOR,
            )
        ]
    if device.tx_power is not None and device.tx_power <= -10:
        return [
            guess(
                "Small wearable or tag",
                Confidence.LOW,
                evidence + ["very low transmit power suggests a small coin-cell device"],
                Category.WEARABLE,
            )
        ]
    return []


# ---------------------------------------------------------------------------
# 7. Apple model inference from proximity-pairing model IDs, as a runner-up
# ---------------------------------------------------------------------------


@matcher("gatt_probe")
def by_probe(device: Device) -> Iterable[Guess]:
    """Re-emit guesses read directly off the device by an active GATT probe.

    A probe reads the model and manufacturer from the device itself, so these
    are the highest-confidence guesses in the system. Routing them through the
    engine (rather than splicing them into ``identification`` at the HTTP layer)
    means the next re-identify tick keeps them ranked first instead of silently
    discarding them.
    """
    return list(getattr(device, "probe_guesses", []) or [])


@matcher("apple_model_table")
def by_apple_model_table(device: Device) -> Iterable[Guess]:
    parsed = device.last_parsed
    if not parsed:
        return []
    for d in parsed.decodings:
        if d.protocol != "apple_proximity_pairing":
            continue
        for f in d.fields:
            if f.name != "model":
                continue
            try:
                model = int(str(f.value), 16)
            except ValueError:
                continue
            name = PROXIMITY_MODELS.get(model)
            if name:
                return [
                    guess(
                        name,
                        Confidence.HIGH,
                        [
                            f"the Proximity Pairing model field is 0x{model:04X}, which "
                            f"is the published identifier for {name}"
                        ],
                        Category.AUDIO,
                        "Apple",
                    )
                ]
    return []
