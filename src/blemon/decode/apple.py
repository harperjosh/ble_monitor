"""Apple manufacturer data (company 0x004C): Continuity, iBeacon, Find My.

Apple devices narrate a surprising amount of their own state, in the clear, to
everyone in radio range. This module makes that readable.

A note on certainty that the whole module is built around: the *structure* of
these messages (type-length-value framing, field widths, which bytes are an
authentication tag) is directly observable and is stated plainly. The *meaning*
of individual status bits is not documented by Apple; it comes from published
reverse-engineering — chiefly Celosia & Cunche, "Discontinued Privacy" (PETS
2020), and the furiousMAC Continuity dissector. Every interpreted bit carries
that provenance in its ``note`` so the UI can render it as an interpretation
rather than as a fact.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from typing import Any

from blemon.decode.registry import manufacturer_decoder
from blemon.models import Category, Decoding, Field_

APPLE_COMPANY_ID = 0x004C

RE = "interpretation from published reverse-engineering, not Apple documentation"

CONTINUITY_TYPES: dict[int, str] = {
    0x01: "Encrypted (unknown subtype 0x01)",
    0x02: "iBeacon",
    0x03: "AirPrint",
    0x05: "AirDrop",
    0x06: "HomeKit",
    0x07: "Proximity Pairing",
    0x08: "Hey Siri",
    0x09: "AirPlay Target",
    0x0A: "AirPlay Source",
    0x0B: "Magic Switch",
    0x0C: "Handoff",
    0x0D: "Tethering Target Presence",
    0x0E: "Tethering Source Presence",
    0x0F: "Nearby Action",
    0x10: "Nearby Info",
    0x11: "Nearby Watch",
    0x12: "Find My",
    0x13: "Audio Sharing",
    0x14: "Shared Audio",
}

NEARBY_ACTION_CODES: dict[int, str] = {
    0x00: "Activity level unknown",
    0x01: "Activity reporting disabled",
    0x03: "Idle user",
    0x05: "Audio playing with the screen off",
    0x07: "Active user (screen on)",
    0x09: "Screen on",
    0x0A: "Watch on wrist and unlocked",
    0x0B: "Recent user activity (possibly driving)",
    0x0D: "Phone call or FaceTime in progress",
    0x0E: "Active user",
}

NEARBY_STATUS_BITS: list[tuple[int, str]] = [
    (0x1, "primary iCloud account signed in"),
    (0x2, "unknown status bit 0x2"),
    (0x4, "AirDrop receiving enabled"),
    (0x8, "unknown status bit 0x8"),
]

NEARBY_DATA_BITS: list[tuple[int, str]] = [
    (0x01, "AirPods connected and screen on"),
    (0x02, "authentication tag present"),
    (0x04, "Wi-Fi on"),
    (0x08, "unknown data bit 0x08"),
    (0x10, "authentication tag present (alt)"),
    (0x20, "Apple Watch locked"),
    (0x40, "Auto Unlock enabled"),
    (0x80, "Auto Unlock (Watch) enabled"),
]

NEARBY_ACTION_TYPES: dict[int, str] = {
    0x01: "Apple TV setup",
    0x04: "Mobile backup",
    0x05: "Watch setup",
    0x06: "Apple TV pairing",
    0x07: "Internet relay",
    0x08: "Wi-Fi password sharing",
    0x09: "iOS setup (Setup New Device prompt)",
    0x0A: "Repair",
    0x0B: "Speaker setup",
    0x0C: "Apple Pay",
    0x0D: "Whole-home audio setup",
    0x0E: "Developer tools pairing",
    0x0F: "Answered call",
    0x10: "Ended call",
    0x11: "DevID ping",
    0x12: "DevID pong",
    0x13: "Companion link proximity",
    0x14: "Remote management",
    0x15: "Remote auto-fill",
    0x16: "Remote display",
    0x17: "Remote camera",
    0x1B: "Setup New Device",
    0x1E: "Phone setup",
    0x20: "HomeKit setup",
    0x27: "Proximity pairing (handover)",
}

#: AirPods and Beats model identifiers seen in Proximity Pairing messages.
PROXIMITY_MODELS: dict[int, str] = {
    0x0220: "AirPods (1st generation)",
    0x0F20: "AirPods (2nd generation)",
    0x1320: "AirPods (3rd generation)",
    0x1920: "AirPods (4th generation)",
    0x1B20: "AirPods (4th generation, ANC)",
    0x0E20: "AirPods Pro",
    0x1420: "AirPods Pro (2nd generation)",
    0x2420: "AirPods Pro (2nd generation, USB-C)",
    0x0A20: "AirPods Max",
    0x1F20: "AirPods Max (USB-C)",
    0x0320: "Powerbeats 3",
    0x0520: "BeatsX",
    0x0620: "Beats Solo 3",
    0x0920: "Beats Studio 3",
    0x0B20: "Powerbeats Pro",
    0x0C20: "Beats Solo Pro",
    0x1120: "Beats Studio Buds",
    0x1020: "Beats Flex",
    0x1720: "Beats Fit Pro",
    0x1220: "Powerbeats 4",
    0x1D20: "Beats Studio Buds+",
}

FINDMY_BATTERY = {0: "full", 1: "medium", 2: "low", 3: "very low"}


def _battery_nibble(value: int) -> str:
    """AirPods encode battery as 0-10 in tens of percent; 15 means unknown."""
    if value == 15:
        return "unknown"
    return f"{min(value, 10) * 10}%"


def _tlvs(data: bytes) -> Iterable[tuple[int, int, int, bytes]]:
    """Yield ``(offset, type, length, value)`` for Continuity TLVs."""
    i = 0
    while i + 1 < len(data):
        t = data[i]
        ln = data[i + 1]
        val = data[i + 2 : i + 2 + ln]
        yield i, t, ln, val
        if ln == 0:
            break
        i += 2 + ln


@manufacturer_decoder(APPLE_COMPANY_ID, name="apple_continuity")
def decode_apple(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    if not data:
        return []
    out: list[Decoding] = []
    for offset, mtype, mlen, value in _tlvs(data):
        name = CONTINUITY_TYPES.get(mtype, f"Unknown Continuity type 0x{mtype:02X}")
        handler = _HANDLERS.get(mtype)
        if handler:
            try:
                out.append(handler(value, offset, context))
                continue
            except Exception:
                pass  # fall through to the structural decoding below
        out.append(
            Decoding(
                protocol="apple_continuity",
                summary=f"Apple {name} ({mlen} bytes)",
                fields=[
                    Field_("continuity_type", f"0x{mtype:02X}", offset, 1, name),
                    Field_("payload", value.hex(), offset + 2, mlen),
                ],
                english=(
                    f"An Apple device is broadcasting a {name} message. "
                    "We can see the message type and length but this subtype's "
                    "contents are not decoded, so the payload is shown as raw bytes."
                ),
                category=Category.PHONE,
                tags=["apple", "continuity", "undecoded_subtype"],
            )
        )
    if not out:
        out.append(
            Decoding(
                protocol="apple_continuity",
                summary=f"Apple manufacturer data, {len(data)} bytes, no valid TLV framing",
                fields=[Field_("payload", data.hex(), 0, len(data))],
                english="Apple manufacturer data that does not follow the usual "
                "type-length-value framing. Shown as raw bytes.",
                category=Category.PHONE,
                tags=["apple"],
            )
        )
    return out


# ---------------------------------------------------------------------------
# Individual Continuity subtypes
# ---------------------------------------------------------------------------


def _ibeacon(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    if len(value) < 21:
        raise ValueError("short iBeacon")
    uuid_raw = value[0:16].hex().upper()
    uuid = f"{uuid_raw[0:8]}-{uuid_raw[8:12]}-{uuid_raw[12:16]}-{uuid_raw[16:20]}-{uuid_raw[20:32]}"
    major, minor = struct.unpack(">HH", value[16:20])
    power = struct.unpack("<b", value[20:21])[0]
    rssi = context.get("rssi")
    distance_hint = ""
    if rssi is not None:
        delta = rssi - power
        if delta > -10:
            distance_hint = " The measured signal suggests you are very close to it."
        elif delta < -30:
            distance_hint = " The measured signal suggests it is some way off."
    return Decoding(
        protocol="ibeacon",
        summary=f"iBeacon {uuid} major={major} minor={minor} @{power}dBm",
        fields=[
            Field_("proximity_uuid", uuid, offset + 2, 16, "identifies the beacon's operator"),
            Field_("major", major, offset + 18, 2, "usually a site or venue"),
            Field_("minor", minor, offset + 20, 2, "usually a specific spot within the site"),
            Field_("measured_power", power, offset + 22, 1, "calibrated RSSI at 1 metre"),
        ],
        english=(
            "This is an iBeacon — a stationary transmitter that does nothing but "
            "announce a fixed identity so apps can tell where you are indoors. "
            f"Its operator UUID is {uuid[:8]}…, at position {major}/{minor}. "
            "It never changes and never listens, so it is a landmark rather than a "
            "participant." + distance_hint
        ),
        category=Category.BEACON,
        tags=["apple", "ibeacon", "static_identity", "plaintext_identity"],
    )


def _nearby_info(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    if len(value) < 2:
        raise ValueError("short Nearby Info")
    status_nibble = value[0] >> 4
    action = value[0] & 0x0F
    data_flags = value[1]
    action_name = NEARBY_ACTION_CODES.get(action, f"unknown action 0x{action:02X}")
    status_names = [n for m, n in NEARBY_STATUS_BITS if status_nibble & m]
    data_names = [n for m, n in NEARBY_DATA_BITS if data_flags & m]

    fields = [
        Field_("action_code", f"0x{action:X}", offset + 2, 1, f"{action_name} — {RE}"),
        Field_("status_flags", status_names, offset + 2, 1, f"raw 0x{status_nibble:X} — {RE}"),
        Field_("data_flags", data_names, offset + 3, 1, f"raw 0x{data_flags:02X} — {RE}"),
    ]
    if len(value) > 2:
        fields.append(
            Field_("auth_tag", value[2:].hex(), offset + 4, len(value) - 2, "rotating, opaque")
        )

    bits = []
    if "Wi-Fi on" in data_names:
        bits.append("Wi-Fi is on")
    if "AirDrop receiving enabled" in status_names:
        bits.append("AirDrop is set to receive")
    if "primary iCloud account signed in" in status_names:
        bits.append("it is signed in to a primary iCloud account")
    extra = ("; ".join(bits) + ". ") if bits else ""

    return Decoding(
        protocol="apple_nearby_info",
        summary=f"Nearby Info: {action_name} (status 0x{status_nibble:X}, data 0x{data_flags:02X})",
        fields=fields,
        english=(
            "This is an Apple device continuously narrating its own state to the room. "
            f"Right now it reports: {action_name.lower()}. {extra}"
            "Nothing here is encrypted — any receiver within range reads it. "
            "The trailing bytes are a rotating authentication tag, which is why the "
            "packet keeps changing even when the device's state does not."
        ),
        category=Category.PHONE,
        tags=["apple", "continuity", "plaintext_state", "device_state_leak"],
    )


def _proximity_pairing(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    if len(value) < 8:
        raise ValueError("short Proximity Pairing")
    model = struct.unpack(">H", value[1:3])[0]
    model_name = PROXIMITY_MODELS.get(model, f"unrecognised model 0x{model:04X}")
    status = value[3]
    pods_batt = value[4]
    flags_case = value[5]
    lid_counter = value[6]
    colour = value[7] if len(value) > 7 else None

    left = _battery_nibble(pods_batt >> 4)
    right = _battery_nibble(pods_batt & 0x0F)
    case = _battery_nibble(flags_case & 0x0F)
    charging = flags_case >> 4
    lid_open = bool(status & 0x08)

    fields = [
        Field_("model", f"0x{model:04X}", offset + 3, 2, model_name),
        Field_("status", f"0x{status:02X}", offset + 5, 1, f"lid open={lid_open} — {RE}"),
        Field_("battery_left", left, offset + 6, 1, RE),
        Field_("battery_right", right, offset + 6, 1, RE),
        Field_("battery_case", case, offset + 7, 1, RE),
        Field_("charging_flags", f"0x{charging:X}", offset + 7, 1, RE),
        Field_("lid_open_counter", lid_counter, offset + 8, 1, "increments each time the case opens"),
    ]
    if colour is not None:
        fields.append(Field_("colour_code", f"0x{colour:02X}", offset + 9, 1, RE))
    if len(value) > 9:
        fields.append(
            Field_("encrypted_payload", value[9:].hex(), offset + 11, len(value) - 9, "encrypted")
        )

    return Decoding(
        protocol="apple_proximity_pairing",
        summary=f"{model_name}: L {left} / R {right} / case {case}",
        fields=fields,
        english=(
            f"A pair of {model_name} is broadcasting its pairing beacon. Anyone in range "
            f"can read the battery levels — left {left}, right {right}, case {case} — and "
            f"a counter showing the case has been opened {lid_counter} times. "
            "That last one is a genuine tracking signal: it is a small, slowly-changing "
            "number unique to this pair of earbuds. The tail of the message is encrypted."
        ),
        category=Category.AUDIO,
        tags=["apple", "airpods", "plaintext_state", "battery_leak", "counter_leak"],
    )


def _handoff(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    if len(value) < 4:
        raise ValueError("short Handoff")
    clipboard = value[0]
    seq = struct.unpack("<H", value[1:3])[0]
    auth = value[3]
    return Decoding(
        protocol="apple_handoff",
        summary=f"Handoff seq={seq} clipboard={clipboard}",
        fields=[
            Field_("clipboard_status", clipboard, offset + 2, 1, RE),
            Field_("sequence_number", seq, offset + 3, 2, "increments per Handoff broadcast"),
            Field_("auth_tag", f"0x{auth:02X}", offset + 5, 1),
            Field_("encrypted_data", value[4:].hex(), offset + 6, len(value) - 4, "encrypted"),
        ],
        english=(
            "This device is advertising Handoff — offering to pass whatever it is doing "
            "to your other Apple devices. The activity itself is encrypted, but the "
            f"sequence number ({seq}) is not, and it increments predictably. Watching that "
            "counter alone reveals how actively the device is being used."
        ),
        category=Category.PHONE,
        tags=["apple", "continuity", "handoff", "counter_leak"],
    )


def _airdrop(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    hashes = []
    if len(value) >= 17:
        for i, label in enumerate(("apple_id", "phone", "email", "email2")):
            h = value[9 + i * 2 : 11 + i * 2]
            if h and h != b"\x00\x00":
                hashes.append((label, h.hex().upper()))
    fields = [Field_("version", value[8] if len(value) > 8 else None, offset + 10, 1)]
    for label, h in hashes:
        fields.append(
            Field_(
                f"{label}_hash",
                h,
                None,
                2,
                "truncated SHA-256 of the contact identifier",
            )
        )
    identifiers = ", ".join(label.replace("_", " ") for label, _ in hashes) or "none"
    return Decoding(
        protocol="apple_airdrop",
        summary=f"AirDrop advertisement, contact hashes present: {identifiers}",
        fields=fields,
        english=(
            "An AirDrop share sheet is open on this device. It is broadcasting short "
            f"hashes of its owner's contact details ({identifiers}). The hashes are only "
            "two bytes each, which is short enough that they can be matched against a "
            "list of known phone numbers or email addresses — this is the well-documented "
            "AirDrop contact-leak."
        ),
        category=Category.PHONE,
        tags=["apple", "airdrop", "contact_hash_leak", "plaintext_identity"],
    )


def _nearby_action(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    if len(value) < 2:
        raise ValueError("short Nearby Action")
    flags = value[0]
    action_type = value[1]
    name = NEARBY_ACTION_TYPES.get(action_type, f"unknown action 0x{action_type:02X}")
    return Decoding(
        protocol="apple_nearby_action",
        summary=f"Nearby Action: {name}",
        fields=[
            Field_("action_flags", f"0x{flags:02X}", offset + 2, 1, RE),
            Field_("action_type", f"0x{action_type:02X}", offset + 3, 1, name),
            Field_("auth_tag", value[2:].hex(), offset + 4, len(value) - 2),
        ],
        english=(
            f"This Apple device is requesting a nearby action: {name}. These messages are "
            "what make the 'set up this device?' and 'share your Wi-Fi password?' prompts "
            "appear on someone else's screen. It is a deliberate, short-lived broadcast, "
            "so seeing one means somebody nearby is actively doing something right now."
        ),
        category=Category.PHONE,
        tags=["apple", "continuity", "user_action"],
    )


def _find_my(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    if not value:
        raise ValueError("empty Find My")
    status = value[0]
    battery = FINDMY_BATTERY.get((status >> 6) & 0x03, "unknown")
    maintained = bool(status & 0x04)
    fields = [
        Field_("status", f"0x{status:02X}", offset + 2, 1, RE),
        Field_("battery_level", battery, offset + 2, 1, f"top two bits — {RE}"),
        Field_("maintained", maintained, offset + 2, 1, "owner has been seen recently"),
    ]
    if len(value) >= 23:
        fields.append(
            Field_(
                "public_key",
                value[1:23].hex().upper(),
                offset + 3,
                22,
                "rotating P-224 public key; changes every 15 minutes",
            )
        )
        kind = "separated"
        detail = (
            "It is broadcasting a rotating cryptographic public key, and every passing "
            "iPhone silently relays an encrypted location report for it to Apple. The key "
            "rotates about every 15 minutes, so this is not by itself a way to follow the "
            "tag over a long period — but it does mean an untracked object nearby is being "
            "located by the entire Apple device population."
        )
    else:
        kind = "nearby"
        detail = (
            "It is in its short 'owner is nearby' form, which means the device it belongs to "
            "is very likely in the room with it."
        )
    return Decoding(
        protocol="apple_find_my",
        summary=f"Find My ({kind}), battery {battery}, maintained={maintained}",
        fields=fields,
        english=(
            f"This is a Find My / offline-finding broadcast — an AirTag, a lost-mode Apple "
            f"device, or a Find My Network accessory. Reported battery: {battery}. {detail}"
        ),
        category=Category.TRACKER,
        tags=["apple", "find_my", "tracker", "rotating_identity"],
    )


def _hey_siri(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    if len(value) < 6:
        raise ValueError("short Hey Siri")
    phash = value[0:2].hex().upper()
    snr = value[2]
    conf = value[3]
    dev_class = struct.unpack("<H", value[4:6])[0]
    return Decoding(
        protocol="apple_hey_siri",
        summary=f"Hey Siri arbitration: SNR {snr}, confidence {conf}",
        fields=[
            Field_("perceptual_hash", phash, offset + 2, 2, "hash of the spoken trigger"),
            Field_("snr", snr, offset + 4, 1, "signal-to-noise of the microphone pickup"),
            Field_("confidence", conf, offset + 5, 1),
            Field_("device_class", f"0x{dev_class:04X}", offset + 6, 2, RE),
        ],
        english=(
            "Somebody just said 'Hey Siri' near this device. When several Apple devices hear "
            "the trigger, they broadcast how well each one heard it and the loudest wins. "
            "Seeing this packet means a voice command happened within the last second or two."
        ),
        category=Category.PHONE,
        tags=["apple", "continuity", "user_action", "plaintext_state"],
    )


def _magic_switch(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    wrist = value[2] if len(value) > 2 else None
    return Decoding(
        protocol="apple_magic_switch",
        summary=f"Magic Switch (Apple Watch wrist state), confidence byte 0x{(wrist or 0):02X}",
        fields=[
            Field_("data", value[:2].hex(), offset + 2, 2),
            Field_("wrist_confidence", wrist, offset + 4, 1, RE),
        ],
        english=(
            "This is an Apple Watch reporting whether it is currently on someone's wrist. "
            "It is used to hand audio between the Watch and a phone. It also means a Watch "
            "is being worn within a few metres of you."
        ),
        category=Category.WEARABLE,
        tags=["apple", "continuity", "wearable", "plaintext_state"],
    )


def _tethering_source(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    if len(value) < 6:
        raise ValueError("short Tethering Source")
    battery = value[2]
    cell_type = struct.unpack("<H", value[3:5])[0]
    bars = value[5]
    return Decoding(
        protocol="apple_tethering_source",
        summary=f"Personal Hotspot available: battery {battery}%, {bars} bars",
        fields=[
            Field_("version", value[0], offset + 2, 1),
            Field_("flags", f"0x{value[1]:02X}", offset + 3, 1, RE),
            Field_("battery_percent", battery, offset + 4, 1),
            Field_("cell_service_type", cell_type, offset + 5, 2, RE),
            Field_("cell_bars", bars, offset + 7, 1),
        ],
        english=(
            "This iPhone is offering its Personal Hotspot. The broadcast is unencrypted and "
            f"includes the phone's battery level ({battery}%) and cellular signal strength "
            f"({bars} bars). Battery percentage is a genuinely identifying signal — it drifts "
            "slowly and predictably, which makes a device easy to re-recognise even after "
            "its address rotates."
        ),
        category=Category.PHONE,
        tags=["apple", "continuity", "hotspot", "battery_leak", "plaintext_state"],
    )


def _tethering_target(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    return Decoding(
        protocol="apple_tethering_target",
        summary="Looking for a Personal Hotspot",
        fields=[Field_("icloud_id", value.hex().upper(), offset + 2, len(value), RE)],
        english=(
            "A device is looking for its owner's Personal Hotspot. It includes a short "
            "identifier derived from the iCloud account, which links this device to the "
            "phone it is trying to reach."
        ),
        category=Category.COMPUTER,
        tags=["apple", "continuity", "account_linkage"],
    )


def _airplay_target(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    ip = ".".join(str(b) for b in value[2:6]) if len(value) >= 6 else None
    return Decoding(
        protocol="apple_airplay_target",
        summary=f"AirPlay target{f' at {ip}' if ip else ''}",
        fields=[
            Field_("flags", f"0x{value[0]:02X}" if value else None, offset + 2, 1, RE),
            Field_("config_seed", value[1] if len(value) > 1 else None, offset + 3, 1),
            Field_("ipv4_address", ip, offset + 4, 4, "the target's address on the local network"),
        ],
        english=(
            "An AirPlay receiver — an Apple TV or a compatible speaker — is announcing itself. "
            + (
                f"It is leaking its local network address, {ip}, over the air, which tells you "
                "the Wi-Fi subnet it sits on without you being on that network."
                if ip
                else "It is advertising availability for screen and audio mirroring."
            )
        ),
        category=Category.APPLIANCE,
        tags=["apple", "airplay", "network_leak", "plaintext_identity"],
    )


def _homekit(value: bytes, offset: int, context: dict[str, Any]) -> Decoding:
    if len(value) < 11:
        raise ValueError("short HomeKit")
    status = value[0]
    dev_id = ":".join(f"{b:02X}" for b in value[1:7])
    category = struct.unpack("<H", value[7:9])[0]
    global_state = struct.unpack("<H", value[9:11])[0]
    paired = not (status & 0x01)
    return Decoding(
        protocol="apple_homekit",
        summary=f"HomeKit accessory {dev_id}, category {category}, paired={paired}",
        fields=[
            Field_("status_flags", f"0x{status:02X}", offset + 2, 1, f"paired={paired} — {RE}"),
            Field_("device_id", dev_id, offset + 3, 6, "stable HomeKit identifier"),
            Field_("accessory_category", category, offset + 9, 2),
            Field_("global_state_number", global_state, offset + 11, 2, "increments on state change"),
        ],
        english=(
            "This is a HomeKit accessory — a smart plug, light, lock or sensor. It broadcasts "
            f"a device identifier ({dev_id}) that does not rotate, so it is permanently "
            "trackable, and a state counter that ticks up every time the accessory changes. "
            "Watching that counter tells you when someone flips the switch."
        ),
        category=Category.APPLIANCE,
        tags=["apple", "homekit", "static_identity", "counter_leak"],
    )


_HANDLERS = {
    0x02: _ibeacon,
    0x05: _airdrop,
    0x06: _homekit,
    0x07: _proximity_pairing,
    0x08: _hey_siri,
    0x09: _airplay_target,
    0x0B: _magic_switch,
    0x0C: _handoff,
    0x0D: _tethering_target,
    0x0E: _tethering_source,
    0x0F: _nearby_action,
    0x10: _nearby_info,
    0x12: _find_my,
}
