"""The accumulated view of one device.

Everything downstream — identification, the radar, the city, the exposure
dashboard, storage — works from this record rather than from individual
packets. It is deliberately bounded: each device keeps a rolling window of
recent observations, not an unbounded history, so a busy room does not grow
without limit. The full history lives in SQLite.
"""

from __future__ import annotations

import math
import statistics
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any

from blemon.decode.hexview import ByteProfile, profile_bytes, summarize_volatility
from blemon.models import (
    AddressType,
    Category,
    Identification,
    ParsedAdvertisement,
    Proximity,
    rssi_to_band,
)

#: How many recent payloads to keep per device for volatility profiling.
PAYLOAD_WINDOW = 24
#: How many recent RSSI readings to keep for smoothing and sparklines.
RSSI_WINDOW = 60
#: How many inter-advertisement gaps to keep for rate estimation.
INTERVAL_WINDOW = 40


# ---------------------------------------------------------------------------
# Exposure scoring
# ---------------------------------------------------------------------------

#: Tags that mean "this device is publishing something about itself or its
#: owner in the clear", with a weight and the phrase shown to the user.
EXPOSURE_SIGNALS: dict[str, tuple[int, str]] = {
    "plaintext_identity": (25, "broadcasts a fixed, readable identity"),
    "plaintext_content": (20, "broadcasts its actual readings or content in the clear"),
    "plaintext_state": (18, "narrates its own state — screen, battery, activity"),
    "static_identity": (22, "uses an identifier that never changes"),
    "contact_hash_leak": (30, "broadcasts hashes of its owner's contact details"),
    "health_data": (30, "broadcasts health measurements"),
    "battery_leak": (10, "broadcasts its battery level"),
    "counter_leak": (12, "broadcasts a counter that uniquely fingerprints it"),
    "mac_in_payload": (25, "repeats its hardware address inside the payload"),
    "device_state_leak": (15, "reveals whether it is in active use"),
    "occupancy_leak": (25, "reveals whether the space it is in is occupied"),
    "network_leak": (20, "reveals its address on the local network"),
    "device_type_leak": (8, "reveals what kind of device it is"),
    "sensitive": (15, "carries information about a person rather than a thing"),
}

#: Tags that mean the opposite — the device is behaving well.
PROTECTION_SIGNALS: dict[str, tuple[int, str]] = {
    "encrypted": (-25, "encrypts its payload"),
    "rotating_identity": (-20, "rotates its identifier"),
    "privacy_preserving": (-25, "uses a deliberately unlinkable design"),
}


@dataclass(slots=True)
class Exposure:
    """How much this device is giving away, and specifically what."""

    score: int  # 0 = shut tight, 100 = wide open
    reasons: list[str] = field(default_factory=list)
    protections: list[str] = field(default_factory=list)

    @property
    def band(self) -> str:
        if self.score >= 70:
            return "wide open"
        if self.score >= 45:
            return "chatty"
        if self.score >= 20:
            return "guarded"
        return "closed"

    @property
    def material(self) -> str:
        """City-view building material. Glass = broadcasting readable identity
        or content in the clear (chatty or wide open); opaque = shuttered.

        Owned here so the city endpoint, the dashboard and the legend all read
        one rule rather than each hardcoding the score cutoff.
        """
        return "glass" if self.band in ("chatty", "wide open") else "opaque"

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band,
            "material": self.material,
            "reasons": self.reasons,
            "protections": self.protections,
        }


# ---------------------------------------------------------------------------
# Device record
# ---------------------------------------------------------------------------


@dataclass
class Device:
    #: Stable key used everywhere. Normally the address; for devices linked
    #: across MAC rotation it is the cluster key, and ``address`` is the
    #: current one.
    key: str
    address: str
    address_type: AddressType = AddressType.UNKNOWN

    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0

    rssi: int | None = None
    rssi_history: deque[tuple[float, int]] = field(default_factory=lambda: deque(maxlen=RSSI_WINDOW))

    names: list[str] = field(default_factory=list)
    service_uuids: list[str] = field(default_factory=list)
    service_names: list[str] = field(default_factory=list)
    company_ids: list[int] = field(default_factory=list)
    company_names: list[str] = field(default_factory=list)
    appearance: int | None = None
    appearance_name: str | None = None
    tx_power: int | None = None
    flags: list[str] = field(default_factory=list)
    connectable: bool | None = None

    protocols: Counter = field(default_factory=Counter)
    tags: Counter = field(default_factory=Counter)
    channels: Counter = field(default_factory=Counter)
    pdu_types: Counter = field(default_factory=Counter)

    #: Every address this device has been seen under (MAC-rotation continuity).
    addresses_seen: list[str] = field(default_factory=list)
    #: Confidence that the addresses above really are one device.
    continuity_confidence: float = 1.0
    continuity_evidence: list[str] = field(default_factory=list)

    payload_window: deque[bytes] = field(default_factory=lambda: deque(maxlen=PAYLOAD_WINDOW))
    intervals: deque[float] = field(default_factory=lambda: deque(maxlen=INTERVAL_WINDOW))

    last_parsed: ParsedAdvertisement | None = None
    identification: Identification | None = None
    user_label: str | None = None
    #: Guesses read directly off the device by an active GATT probe. Stored on
    #: the device (not spliced into ``identification``) so they survive the next
    #: re-identify tick — the engine's gatt_probe matcher re-emits them.
    probe_guesses: list[Any] = field(default_factory=list)
    #: Marked by the user as their own hardware; required for probe allowlist mode.
    is_mine: bool = False
    notes: str | None = None

    sources: set[str] = field(default_factory=set)
    #: Set when a sniffer has followed a connection involving this device.
    link_event_count: int = 0
    encrypted_link_seen: bool = False
    plaintext_link_seen: bool = False

    # -- ingest ------------------------------------------------------------

    def observe(self, parsed: ParsedAdvertisement) -> None:
        adv = parsed.advertisement
        now = adv.timestamp

        if self.packet_count:
            gap = now - self.last_seen
            if 0 < gap < 30:
                self.intervals.append(gap)
        self.last_seen = now
        self.packet_count += 1
        self.address = adv.address
        if adv.address_type is not AddressType.UNKNOWN:
            self.address_type = adv.address_type
        if adv.address not in self.addresses_seen:
            self.addresses_seen.append(adv.address)

        if adv.rssi is not None:
            self.rssi = adv.rssi
            self.rssi_history.append((now, adv.rssi))
        if adv.channel:
            self.channels[adv.channel] += 1
        self.pdu_types[adv.pdu_type.value] += 1
        self.sources.add(adv.source)
        if adv.connectable is not None:
            self.connectable = adv.connectable
        if adv.raw:
            self.payload_window.append(adv.raw)

        if parsed.local_name and parsed.local_name not in self.names:
            self.names.append(parsed.local_name)
        for uuid, name in zip(parsed.service_uuids, parsed.service_names, strict=True):
            if uuid not in self.service_uuids:
                self.service_uuids.append(uuid)
                self.service_names.append(name)
        for cid, name in zip(parsed.company_ids, parsed.company_names, strict=True):
            if cid not in self.company_ids:
                self.company_ids.append(cid)
                self.company_names.append(name)
        if parsed.appearance is not None:
            self.appearance = parsed.appearance
            self.appearance_name = parsed.appearance_name
        if parsed.tx_power is not None:
            self.tx_power = parsed.tx_power
        if parsed.flags:
            self.flags = parsed.flags

        for decoding in parsed.decodings:
            self.protocols[decoding.protocol] += 1
            for tag in decoding.tags:
                self.tags[tag] += 1

        self.last_parsed = parsed

    def absorb(self, other: Device, confidence: float, evidence: list[str]) -> None:
        """Fold another address's record into this one after a continuity match."""
        self.packet_count += other.packet_count
        self.first_seen = min(self.first_seen, other.first_seen)
        if other.last_seen > self.last_seen:
            self.last_seen = other.last_seen
            self.address = other.address
            self.address_type = other.address_type
            self.rssi = other.rssi
            self.last_parsed = other.last_parsed
        for a in other.addresses_seen:
            if a not in self.addresses_seen:
                self.addresses_seen.append(a)
        for n in other.names:
            if n not in self.names:
                self.names.append(n)
        for u, sn in zip(other.service_uuids, other.service_names, strict=True):
            if u not in self.service_uuids:
                self.service_uuids.append(u)
                self.service_names.append(sn)
        for c, cn in zip(other.company_ids, other.company_names, strict=True):
            if c not in self.company_ids:
                self.company_ids.append(c)
                self.company_names.append(cn)
        self.protocols.update(other.protocols)
        self.tags.update(other.tags)
        self.channels.update(other.channels)
        self.pdu_types.update(other.pdu_types)
        self.sources |= other.sources
        self.rssi_history.extend(other.rssi_history)
        self.payload_window.extend(other.payload_window)
        self.intervals.extend(other.intervals)
        # Preserve the user's own annotations and any observed link state across
        # a merge. Dropping is_mine here would resurrect tracker alerts for the
        # user's own device and lock it out of the probe allowlist; dropping the
        # link flags would corrupt the encrypted-vs-plaintext exposure stats.
        self.is_mine = self.is_mine or other.is_mine
        if not self.user_label and other.user_label:
            self.user_label = other.user_label
        if not self.notes and other.notes:
            self.notes = other.notes
        self.link_event_count += other.link_event_count
        self.encrypted_link_seen = self.encrypted_link_seen or other.encrypted_link_seen
        self.plaintext_link_seen = self.plaintext_link_seen or other.plaintext_link_seen
        self.continuity_confidence = min(self.continuity_confidence, confidence)
        for e in evidence:
            if e not in self.continuity_evidence:
                self.continuity_evidence.append(e)

    # -- derived -----------------------------------------------------------

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def advertising_rate(self) -> float:
        """Advertisements per second, from the median inter-packet gap."""
        if len(self.intervals) >= 3:
            median = statistics.median(self.intervals)
            if median > 0:
                return 1.0 / median
        if self.duration > 1 and self.packet_count > 1:
            return self.packet_count / self.duration
        return 0.0

    @property
    def proximity(self) -> Proximity:
        return rssi_to_band(self.smoothed_rssi)

    @property
    def smoothed_rssi(self) -> int | None:
        """Median of the last few readings — raw RSSI is far too jumpy to plot."""
        if not self.rssi_history:
            return self.rssi
        recent = [r for _, r in list(self.rssi_history)[-7:]]
        return int(round(statistics.median(recent)))

    @property
    def rssi_range(self) -> tuple[int, int] | None:
        if not self.rssi_history:
            return None
        values = [r for _, r in self.rssi_history]
        return min(values), max(values)

    @property
    def display_name(self) -> str:
        if self.user_label:
            return self.user_label
        if self.identification:
            return self.identification.display_label
        if self.names:
            return self.names[0]
        return "Unidentified device"

    @property
    def category(self) -> Category:
        if self.identification:
            return self.identification.category
        return Category.UNKNOWN

    @property
    def is_tracker(self) -> bool:
        return "tracker" in self.tags

    @property
    def rotates_address(self) -> bool:
        return self.address_type.is_rotating or len(self.addresses_seen) > 1

    def byte_profiles(self) -> list[ByteProfile]:
        return profile_bytes(list(self.payload_window))

    def volatility_summary(self) -> str:
        return summarize_volatility(self.byte_profiles())

    def exposure(self) -> Exposure:
        score = 0
        reasons: list[str] = []
        protections: list[str] = []

        for tag, (weight, phrase) in EXPOSURE_SIGNALS.items():
            if tag in self.tags:
                score += weight
                reasons.append(phrase)
        for tag, (weight, phrase) in PROTECTION_SIGNALS.items():
            if tag in self.tags:
                score += weight
                protections.append(phrase)

        if self.address_type.is_stable:
            score += 20
            reasons.append(
                "uses a permanent address, so it is trackable across days without any "
                "other information"
            )
        elif self.address_type is AddressType.RESOLVABLE_PRIVATE:
            score -= 10
            protections.append("uses a resolvable private address that rotates")
        elif self.address_type is AddressType.NON_RESOLVABLE_PRIVATE:
            score -= 15
            protections.append("uses a non-resolvable private address")

        if self.names:
            score += 12
            reasons.append(f"broadcasts a readable name (“{self.names[0]}”)")

        if self.plaintext_link_seen:
            score += 20
            reasons.append("was observed exchanging unencrypted data over a connection")
        if self.encrypted_link_seen:
            score -= 15
            protections.append("encrypts its connections")

        return Exposure(score=max(0, min(100, score)), reasons=reasons, protections=protections)

    # -- placement ---------------------------------------------------------

    def stable_hash(self) -> int:
        """A deterministic hash of identity, used for radar angle and city lots.

        Derived from the most stable thing we know about the device so that a
        given device lands in the same place every session. For a device that
        rotates its address, that means the first address we ever saw it under
        within a cluster — which is stable for the lifetime of the cluster.
        """
        seed = self.key
        # Prefer something that survives address rotation when we have it.
        if self.names:
            seed = f"name:{self.names[0]}"
        elif self.company_ids and self.service_uuids:
            seed = f"co:{self.company_ids[0]}:svc:{','.join(sorted(self.service_uuids))}"
        h = 0
        for ch in seed:
            h = (h * 31 + ord(ch)) & 0xFFFFFFFF
        return h

    @property
    def radar_angle(self) -> float:
        """Radians. Arbitrary but stable — BLE gives us no bearing at all."""
        return (self.stable_hash() % 36000) / 36000.0 * 2 * math.pi

    def to_dict(self, include_decode: bool = False) -> dict[str, Any]:
        rng = self.rssi_range
        d: dict[str, Any] = {
            "key": self.key,
            "address": self.address,
            "address_type": self.address_type.value,
            "address_is_rotating": self.rotates_address,
            "addresses_seen": self.addresses_seen,
            "continuity_confidence": round(self.continuity_confidence, 3),
            "continuity_evidence": self.continuity_evidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": round(self.duration, 2),
            "packet_count": self.packet_count,
            "rssi": self.rssi,
            "rssi_smoothed": self.smoothed_rssi,
            "rssi_min": rng[0] if rng else None,
            "rssi_max": rng[1] if rng else None,
            "rssi_history": [[round(t, 2), r] for t, r in self.rssi_history],
            "proximity": self.proximity.value,
            "advertising_rate": round(self.advertising_rate, 3),
            "names": self.names,
            "display_name": self.display_name,
            "service_uuids": self.service_uuids,
            "service_names": self.service_names,
            "company_ids": self.company_ids,
            "company_names": self.company_names,
            "appearance": self.appearance,
            "appearance_name": self.appearance_name,
            "tx_power": self.tx_power,
            "flags": self.flags,
            "connectable": self.connectable,
            "protocols": dict(self.protocols),
            "tags": dict(self.tags),
            "channels": {str(k): v for k, v in self.channels.items()},
            "pdu_types": dict(self.pdu_types),
            "category": self.category.value,
            "is_tracker": self.is_tracker,
            "is_mine": self.is_mine,
            "user_label": self.user_label,
            "notes": self.notes,
            "sources": sorted(self.sources),
            "identification": self.identification.to_dict() if self.identification else None,
            "exposure": self.exposure().to_dict(),
            "radar_angle": round(self.radar_angle, 5),
            "stable_hash": self.stable_hash(),
            "link_event_count": self.link_event_count,
            "encrypted_link_seen": self.encrypted_link_seen,
            "plaintext_link_seen": self.plaintext_link_seen,
        }
        if include_decode:
            d["last_advertisement"] = self.last_parsed.to_dict() if self.last_parsed else None
            d["byte_profiles"] = [p.to_dict() for p in self.byte_profiles()]
            d["volatility_summary"] = self.volatility_summary()
        return d
