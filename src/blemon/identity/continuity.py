"""Continuity across MAC rotation.

Modern phones change their Bluetooth address roughly every 15 minutes,
specifically so that you cannot do what this module does. Without some
correlation, a single iPhone sitting on a table for an hour appears as four or
five separate devices and every count on the dashboard becomes meaningless.

So this exists to make counts honest, and it is deliberately conservative:

* Only devices that actually rotate their address are considered.
* A fingerprint has to be *specific* before it is allowed to link anything. Two
  iPhones broadcasting nothing but a generic Nearby Info message look identical
  to each other, and linking those would be worse than not linking at all.
* The result is always an explicitly labelled, confidence-scored inference with
  its evidence attached, never a certainty, and it stays local.

The purpose is an accurate picture of the room. It is not a dossier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from blemon.device import Device

#: Below this, a fingerprint is too generic to justify linking anything.
MIN_SPECIFICITY = 28

#: A rotated address should appear at roughly the moment the old one vanished.
DEFAULT_WINDOW_SECONDS = 150.0

#: RSSI should not jump wildly across a rotation — the device did not teleport.
MAX_RSSI_DELTA = 18

#: Correlation can never be certain, so cap it well below 1.0.
MAX_CONFIDENCE = 0.85


@dataclass(frozen=True)
class Fingerprint:
    """The parts of a device's behaviour that survive an address change.

    ``key`` holds only *hard* signals — things that are either identical across
    a rotation or not. Anything estimated, such as the advertising rate, is a
    soft signal: it adjusts confidence but must never be part of the equality
    test, because a few tenths of jitter in a rate estimate would silently stop
    two halves of the same device from ever matching.
    """

    key: tuple
    specificity: int
    parts: tuple[str, ...] = field(default=())
    #: Estimated advertising rate, compared loosely rather than exactly.
    rate: float = 0.0

    @property
    def linkable(self) -> bool:
        return self.specificity >= MIN_SPECIFICITY


def fingerprint(device: Device) -> Fingerprint:
    """Derive a rotation-invariant fingerprint and score how distinctive it is."""
    parts: list[str] = []
    score = 0
    key: list = []

    if device.names:
        name = device.names[0]
        key.append(("name", name))
        parts.append(f"advertises the name “{name}”")
        score += 50

    if device.service_uuids:
        uuids = tuple(sorted(device.service_uuids))
        key.append(("services", uuids))
        parts.append(f"advertises service UUIDs {', '.join(uuids)}")
        score += 10 * len(uuids)

    if device.company_ids:
        cids = tuple(sorted(device.company_ids))
        key.append(("companies", cids))
        parts.append("uses company ID " + ", ".join(f"0x{c:04X}" for c in cids))
        score += 5

    # Which Apple Continuity subtypes (or other protocols) it emits is quite
    # distinctive: an iPhone with Handoff plus a hotspot looks different from
    # one that only sends Nearby Info.
    if device.protocols:
        protos = tuple(sorted(device.protocols))
        key.append(("protocols", protos))
        parts.append("emits " + ", ".join(protos))
        score += 8 * len(protos)

    if device.appearance is not None:
        key.append(("appearance", device.appearance))
        parts.append(f"declares appearance 0x{device.appearance:04X}")
        score += 15

    if device.tx_power is not None:
        key.append(("tx", device.tx_power))
        parts.append(f"declares TX power {device.tx_power} dBm")
        score += 5

    if device.last_parsed and device.last_parsed.advertisement.raw:
        length = len(device.last_parsed.advertisement.raw)
        key.append(("length", length))
        parts.append(f"payload is consistently {length} bytes")
        score += 3
        structure = tuple(s.type_code for s in device.last_parsed.structures)
        key.append(("structure", structure))
        parts.append(
            "AD structure layout is " + "/".join(f"0x{t:02X}" for t in structure)
        )
        score += 4 * len(structure)

    rate = device.advertising_rate
    if rate > 0:
        parts.append(f"advertises at about {rate:.1f}/s")

    return Fingerprint(key=tuple(key), specificity=score, parts=tuple(parts), rate=rate)


@dataclass
class Link:
    """A proposed link between a retired address and a new one."""

    old_key: str
    new_key: str
    confidence: float
    evidence: list[str]


def propose_link(
    old: Device,
    new: Device,
    window: float = DEFAULT_WINDOW_SECONDS,
) -> Link | None:
    """Decide whether ``new`` is ``old`` under a fresh address.

    Returns None whenever we cannot justify the link, which is the common case
    and the correct default.
    """
    if old.key == new.key:
        return None
    if not old.rotates_address or not new.rotates_address:
        return None
    if new.address in old.addresses_seen:
        return None
    # A successor cannot predate its predecessor. Without this the overlap
    # tolerance below happily links a device *backwards* to one that appeared
    # after it, which silently merges two genuinely different devices.
    if new.first_seen <= old.first_seen:
        return None

    fp_old = fingerprint(old)
    fp_new = fingerprint(new)
    if fp_old.key != fp_new.key:
        return None
    if not fp_old.linkable:
        return None

    gap = new.first_seen - old.last_seen
    # The new address must appear around the time the old one went quiet. A
    # small negative gap is normal: controllers often overlap briefly.
    if gap > window or gap < -30:
        return None

    evidence = list(fp_old.parts)
    evidence.append(
        f"the new address appeared {gap:.0f}s after the old one stopped transmitting"
    )

    confidence = min(0.75, 0.35 + fp_old.specificity / 200.0)

    # Temporal tightness raises confidence; a long silence lowers it.
    if 0 <= gap <= 20:
        confidence += 0.10
        evidence.append("the changeover was near-instant, as a scheduled rotation would be")
    elif gap > window * 0.7:
        confidence -= 0.10

    old_rssi = old.smoothed_rssi
    new_rssi = new.smoothed_rssi
    if old_rssi is not None and new_rssi is not None:
        delta = abs(old_rssi - new_rssi)
        if delta > MAX_RSSI_DELTA:
            return None
        if delta <= 6:
            confidence += 0.08
            evidence.append(
                f"signal strength barely moved across the change ({old_rssi} to {new_rssi} dBm)"
            )
        else:
            evidence.append(f"signal strength went from {old_rssi} to {new_rssi} dBm")

    if old.address_type is new.address_type:
        evidence.append(
            f"both addresses are of the same type ({old.address_type.value.replace('_', ' ')})"
        )
        confidence += 0.04

    # Advertising rate is a soft signal: close rates corroborate, wildly
    # different ones argue against, but neither is decisive on its own.
    if fp_old.rate > 0 and fp_new.rate > 0:
        ratio = max(fp_old.rate, fp_new.rate) / min(fp_old.rate, fp_new.rate)
        if ratio <= 1.35:
            confidence += 0.05
            evidence.append(
                f"both advertise at a similar rate ({fp_old.rate:.1f}/s then {fp_new.rate:.1f}/s)"
            )
        elif ratio > 3.0:
            confidence -= 0.15
            evidence.append(
                f"advertising rate changed noticeably ({fp_old.rate:.1f}/s to {fp_new.rate:.1f}/s)"
            )

    confidence = max(0.3, min(MAX_CONFIDENCE, confidence))
    return Link(old_key=old.key, new_key=new.key, confidence=confidence, evidence=evidence)


def find_links(
    devices: list[Device],
    window: float = DEFAULT_WINDOW_SECONDS,
) -> list[Link]:
    """Propose links across a whole device set, best candidate per new device."""
    rotating = [d for d in devices if d.rotates_address]
    by_start = sorted(rotating, key=lambda d: d.first_seen)
    links: list[Link] = []
    consumed: set[str] = set()

    for new in by_start:
        best: Link | None = None
        for old in rotating:
            if old.key in consumed or old.last_seen > new.first_seen + 30:
                continue
            link = propose_link(old, new, window)
            if link and (best is None or link.confidence > best.confidence):
                best = link
        if best:
            consumed.add(best.old_key)
            links.append(best)
    return links


def apply_links(devices: dict[str, Device], links: list[Link]) -> dict[str, Device]:
    """Collapse linked addresses into clusters, in place, and return the result.

    The **oldest** record in a chain keeps its key and absorbs the newer ones.
    That matters: the key drives the city view's lot placement and the client's
    device identity, so it has to stay put for the life of the cluster rather
    than jumping to whichever address is current.

    Chains are resolved transitively, so an address that has rotated four times
    ends up as one device and not two pairs.
    """
    parent: dict[str, str] = {}

    def root(k: str) -> str:
        seen = []
        while k in parent:
            seen.append(k)
            k = parent[k]
        for s in seen:
            parent[s] = k
        return k

    # Oldest-first so the eldest record always wins the root position.
    ordered = sorted(links, key=lambda link: devices[link.new_key].first_seen
                     if link.new_key in devices else 0.0)
    for link in ordered:
        if link.old_key not in devices or link.new_key not in devices:
            continue
        a, b = root(link.old_key), root(link.new_key)
        if a == b:
            continue
        elder, younger = (a, b) if devices[a].first_seen <= devices[b].first_seen else (b, a)
        parent[younger] = elder
        devices[elder].absorb(devices[younger], link.confidence, link.evidence)

    for key in list(devices):
        if key in parent:
            devices.pop(key, None)
    return devices


def explain_absence(device: Device) -> str:
    """Why a device could *not* be linked — shown in the UI, because silence
    about a failed inference is itself misleading."""
    fp = fingerprint(device)
    if not device.rotates_address:
        return (
            "This device uses a fixed address, so there is nothing to correlate — it is "
            "simply the same device every time you see it."
        )
    if not fp.linkable:
        return (
            "This device rotates its address and broadcasts nothing distinctive enough to "
            "recognise it afterwards. That is the privacy design working: we genuinely "
            "cannot tell whether you have seen it before."
        )
    return (
        "This device rotates its address and has a distinctive enough fingerprint to "
        "correlate, but no earlier address matched it in this session."
    )
