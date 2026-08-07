"""The plain-English layer.

This is the point of the project. A packet dump plus a field table is still
opaque; a sentence that says what a device is doing and why it matters is what
turns it into understanding.

Individual decoders each produce a sentence about their own payload
(``Decoding.english``). This module works one level up: it takes everything
known about a *device* and writes the short paragraph that appears at the top
of its detail panel, plus the one-liners the radar and city views use on hover.

Rules the wording follows throughout:

* Say what was observed, not what is probably true. "Broadcasts a fixed
  address" is an observation. "Belongs to a stranger" is not.
* Never state a guess as a fact. When the label is inferred, say so in the
  sentence itself.
* Prefer the consequence to the mechanism. "Anyone in range can read its
  battery level" lands; "exposes characteristic 0x2A19" does not.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from blemon.models import AddressType, Confidence, Proximity

if TYPE_CHECKING:  # pragma: no cover
    from blemon.device import Device

PROXIMITY_PHRASE = {
    Proximity.IMMEDIATE: "within a metre or two",
    Proximity.NEAR: "somewhere in this room",
    Proximity.FAR: "in range but not close",
    Proximity.DISTANT: "at the edge of range",
}

#: Phrased so no indefinite article is needed. "an AirPods Pro" and "a Windows
#: laptop" cannot both be produced by one rule, and a wrong article reads as
#: carelessness in the one sentence that is meant to carry the most weight.
CONFIDENCE_PHRASE = {
    Confidence.CERTAIN: "Identified as",
    Confidence.HIGH: "Almost certainly",
    Confidence.MEDIUM: "Looks like",
    Confidence.LOW: "Might be",
}

ADDRESS_PHRASE = {
    AddressType.PUBLIC: (
        "It uses a permanent, globally unique hardware address. That address will be the "
        "same tomorrow and next year, so anyone who has seen it once can recognise it "
        "again anywhere."
    ),
    AddressType.RANDOM_STATIC: (
        "It uses a random address that stays fixed until it reboots — better than a "
        "permanent one, but still stable enough to follow for as long as it stays on."
    ),
    AddressType.RESOLVABLE_PRIVATE: (
        "It rotates its address roughly every 15 minutes, which is the modern privacy "
        "behaviour: only devices that have been paired with it can tell it is the same "
        "device across rotations."
    ),
    AddressType.NON_RESOLVABLE_PRIVATE: (
        "It uses a fully random address that nothing can resolve back to a stable "
        "identity — the most private option available."
    ),
    AddressType.OPAQUE: (
        "macOS will not give us this device's real address, only a per-application "
        "identifier, so we cannot say anything about its address privacy. Capturing on a "
        "Linux machine or a Raspberry Pi would show you the real thing."
    ),
    AddressType.UNKNOWN: "We could not determine how its address is allocated.",
}


def rate_phrase(rate: float) -> str:
    if rate <= 0:
        return "We have not seen it often enough to judge how chatty it is."
    if rate >= 10:
        return f"It is extremely chatty — about {rate:.0f} advertisements every second."
    if rate >= 2:
        return f"It advertises briskly, roughly {rate:.1f} times a second."
    if rate >= 0.4:
        return f"It advertises steadily, about once every {1 / rate:.1f} seconds."
    return f"It advertises rarely, roughly once every {1 / rate:.0f} seconds — battery-conscious."


def describe_device(device: Device) -> str:
    """The paragraph shown at the top of a device's detail panel."""
    parts: list[str] = []
    ident = device.identification

    if device.user_label:
        parts.append(f"You have labelled this device “{device.user_label}”.")
    elif ident and ident.best:
        opener = CONFIDENCE_PHRASE.get(ident.best.confidence, "Might be")
        parts.append(f"{opener} {ident.best.label}.")
        if ident.runners_up:
            alts = ", ".join(g.label for g in ident.runners_up[:2])
            parts.append(f"It could also be {alts} — the evidence is listed below.")
    else:
        parts.append(
            "We cannot identify this device. It broadcasts nothing that matches anything "
            "we know about."
        )

    parts.append(
        f"It is {PROXIMITY_PHRASE[device.proximity]}"
        + (f" (signal {device.smoothed_rssi} dBm)." if device.smoothed_rssi is not None else ".")
    )

    parts.append(rate_phrase(device.advertising_rate))
    parts.append(ADDRESS_PHRASE.get(device.address_type, ADDRESS_PHRASE[AddressType.UNKNOWN]))

    if len(device.addresses_seen) > 1:
        parts.append(
            f"We have linked {len(device.addresses_seen)} different addresses to this one "
            f"device, with {device.continuity_confidence:.0%} confidence. That is an "
            "inference from its payload shape, not a certainty — the reasoning is shown "
            "under continuity."
        )

    exposure = device.exposure()
    if exposure.reasons:
        parts.append(
            f"On exposure it reads as {exposure.band}: it "
            + _join(exposure.reasons[:3])
            + "."
        )
    if exposure.protections:
        parts.append("In its favour, it " + _join(exposure.protections[:2]) + ".")

    if device.last_parsed:
        highlights = [d.english for d in device.last_parsed.decodings if d.english]
        if highlights:
            parts.append(highlights[0])

    if not device.protocols and device.payload_window:
        parts.append(device.volatility_summary())

    return " ".join(p for p in parts if p)


def one_liner(device: Device) -> str:
    """The single sentence shown on hover in the radar and city views."""
    label = device.display_name
    ident = device.identification
    hedge = ""
    if not device.user_label and ident and ident.best:
        if ident.best.confidence in (Confidence.LOW, Confidence.MEDIUM):
            hedge = " (best guess)"
    prox = PROXIMITY_PHRASE[device.proximity]
    rate = device.advertising_rate
    chat = f", {rate:.1f} adverts/s" if rate >= 0.05 else ""
    return f"{label}{hedge} — {prox}{chat}."


def describe_room(devices: list[Device]) -> str:
    """The summary sentence for the whole environment."""
    if not devices:
        return (
            "Nothing is being received. Either there is genuinely no BLE traffic in range, "
            "or the capture backend cannot see the radio — run `blemon doctor` to tell "
            "which."
        )

    total = len(devices)
    trackers = sum(1 for d in devices if d.is_tracker)
    rotating = sum(1 for d in devices if d.rotates_address)
    named = sum(1 for d in devices if d.names)
    # Count via the band classification that Exposure owns, so this sentence and
    # the exposure dashboard's "wide open" tally never drift apart.
    wide_open = sum(1 for d in devices if d.exposure().band == "wide open")

    bits = [f"{total} device{'s' if total != 1 else ''} in range."]
    bits.append(
        f"{rotating} of them rotate their address to resist tracking; "
        f"{total - rotating} do not and are followable indefinitely."
    )
    if named:
        bits.append(f"{named} broadcast a readable name.")
    if wide_open:
        bits.append(
            f"{wide_open} are wide open — publishing identity, state or measurements that "
            "anyone in range can read."
        )
    if trackers:
        bits.append(
            f"{trackers} {'is' if trackers == 1 else 'are'} item tracker"
            f"{'' if trackers == 1 else 's'}."
        )
    return " ".join(bits)


def _join(items: list[str]) -> str:
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f" and {items[-1]}"
