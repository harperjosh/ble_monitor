"""Core data model shared by every layer.

These types are the contract between capture, decode, identity, translation,
storage and the API. They are plain dataclasses with explicit ``to_dict``
methods rather than pydantic models so the decode layer stays importable
without any web dependency, and so fixtures can be diffed as plain JSON.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Addressing
# ---------------------------------------------------------------------------


class AddressType(str, Enum):
    """How a device's advertised address is allocated.

    This is the single most informative privacy signal in an advertisement:
    a device using a public address is permanently, trivially trackable, while
    one using a resolvable private address is actively trying not to be.
    """

    PUBLIC = "public"
    RANDOM_STATIC = "random_static"
    RESOLVABLE_PRIVATE = "resolvable_private"
    NON_RESOLVABLE_PRIVATE = "non_resolvable_private"
    #: macOS hands us an opaque per-application UUID instead of a MAC, so we
    #: genuinely do not know. Never guess one of the above in this case.
    OPAQUE = "opaque"
    UNKNOWN = "unknown"

    @property
    def is_rotating(self) -> bool:
        return self in (
            AddressType.RESOLVABLE_PRIVATE,
            AddressType.NON_RESOLVABLE_PRIVATE,
        )

    @property
    def is_stable(self) -> bool:
        return self in (AddressType.PUBLIC, AddressType.RANDOM_STATIC)


def classify_address(addr: str, random: bool) -> AddressType:
    """Classify a BLE address from its top two bits, per Core Spec Vol 6 Part B.

    ``addr`` is the human-readable big-endian form ("AA:BB:CC:DD:EE:FF").
    """
    if not random:
        return AddressType.PUBLIC
    try:
        msb = int(addr.split(":")[0], 16)
    except (ValueError, IndexError):
        return AddressType.UNKNOWN
    top = msb >> 6
    if top == 0b11:
        return AddressType.RANDOM_STATIC
    if top == 0b01:
        return AddressType.RESOLVABLE_PRIVATE
    if top == 0b00:
        return AddressType.NON_RESOLVABLE_PRIVATE
    return AddressType.UNKNOWN  # 0b10 is reserved for future use


# ---------------------------------------------------------------------------
# Categories and proximity
# ---------------------------------------------------------------------------


class Category(str, Enum):
    """Coarse device class, used for colour and city districts."""

    PHONE = "phone"
    COMPUTER = "computer"
    WEARABLE = "wearable"
    AUDIO = "audio"
    TRACKER = "tracker"
    BEACON = "beacon"
    APPLIANCE = "appliance"
    SENSOR = "sensor"
    VEHICLE = "vehicle"
    MEDICAL = "medical"
    PERIPHERAL = "peripheral"
    NETWORK = "network"
    UNKNOWN = "unknown"


class Proximity(str, Enum):
    """Coarse distance band.

    RSSI-to-metres conversion is unreliable enough that presenting metres would
    be a fabrication. We present bands and say so.
    """

    IMMEDIATE = "immediate"
    NEAR = "near"
    FAR = "far"
    DISTANT = "distant"


def rssi_to_band(rssi: int | None) -> Proximity:
    if rssi is None:
        return Proximity.DISTANT
    if rssi >= -55:
        return Proximity.IMMEDIATE
    if rssi >= -70:
        return Proximity.NEAR
    if rssi >= -85:
        return Proximity.FAR
    return Proximity.DISTANT


class Confidence(str, Enum):
    CERTAIN = "certain"  # reserved for things read directly off the wire
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def score(self) -> float:
        return {"certain": 1.0, "high": 0.8, "medium": 0.55, "low": 0.3}[self.value]


# ---------------------------------------------------------------------------
# Capture events
# ---------------------------------------------------------------------------


class PduType(str, Enum):
    ADV_IND = "ADV_IND"
    ADV_DIRECT_IND = "ADV_DIRECT_IND"
    ADV_NONCONN_IND = "ADV_NONCONN_IND"
    SCAN_REQ = "SCAN_REQ"
    SCAN_RSP = "SCAN_RSP"
    CONNECT_IND = "CONNECT_IND"
    ADV_SCAN_IND = "ADV_SCAN_IND"
    ADV_EXT_IND = "ADV_EXT_IND"
    AUX_ADV_IND = "AUX_ADV_IND"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class Advertisement:
    """One received advertising packet, before protocol decoding.

    ``address`` is whatever stable-ish handle the backend can give us. On Linux
    that is a real MAC; on macOS it is a CoreBluetooth per-application UUID and
    ``address_type`` will be OPAQUE.
    """

    address: str
    timestamp: float = field(default_factory=time.time)
    rssi: int | None = None
    address_type: AddressType = AddressType.UNKNOWN
    #: Raw AD payload, exactly as received. Never discarded — the byte-level
    #: view and PCAP export both need it.
    raw: bytes = b""
    #: Advertising channel 37/38/39 when the backend knows it.
    channel: int | None = None
    pdu_type: PduType = PduType.UNKNOWN
    phy: str = "1M"
    #: True when this payload arrived in a SCAN_RSP rather than an ADV.
    scan_response: bool = False
    connectable: bool | None = None
    tx_power_adv: int | None = None
    #: Which backend produced it, for provenance in the UI.
    source: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["raw"] = self.raw.hex()
        d["address_type"] = self.address_type.value
        d["pdu_type"] = self.pdu_type.value
        return d


@dataclass(slots=True)
class LinkEvent:
    """A connection-layer event, only available with sniffer hardware."""

    timestamp: float
    kind: str  # connect | data | disconnect | encryption | mtu | gatt
    address: str | None = None
    summary: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    encrypted: bool = False
    direction: str | None = None  # central | peripheral
    raw: bytes = b""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["raw"] = self.raw.hex()
        return d


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Field_:
    """One named value pulled out of a payload, with the bytes it came from."""

    name: str
    value: Any
    #: Byte offset within the enclosing structure's data, when meaningful.
    offset: int | None = None
    length: int | None = None
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Decoding:
    """The output of one protocol decoder over one AD structure."""

    protocol: str  # "apple_continuity", "eddystone", ...
    summary: str  # short technical one-liner
    fields: list[Field_] = field(default_factory=list)
    #: Ordinary-English explanation. This is the whole point of the project.
    english: str = ""
    #: Category hint this decoding implies, if any.
    category: Category | None = None
    #: Free-form tags used by the exposure dashboard, e.g. "plaintext_state".
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "summary": self.summary,
            "fields": [f.to_dict() for f in self.fields],
            "english": self.english,
            "category": self.category.value if self.category else None,
            "tags": list(self.tags),
        }


@dataclass(slots=True)
class ADStructure:
    """One length-type-value element of an advertising payload."""

    type_code: int
    type_name: str
    data: bytes
    offset: int
    decodings: list[Decoding] = field(default_factory=list)
    #: Structured interpretation of the AD type itself (names, UUIDs, flags).
    fields: list[Field_] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type_code": self.type_code,
            "type_name": self.type_name,
            "data": self.data.hex(),
            "offset": self.offset,
            "fields": [f.to_dict() for f in self.fields],
            "decodings": [d.to_dict() for d in self.decodings],
        }


@dataclass(slots=True)
class ParsedAdvertisement:
    """An advertisement after AD parsing and protocol decoding."""

    advertisement: Advertisement
    structures: list[ADStructure] = field(default_factory=list)
    local_name: str | None = None
    tx_power: int | None = None
    appearance: int | None = None
    appearance_name: str | None = None
    company_ids: list[int] = field(default_factory=list)
    company_names: list[str] = field(default_factory=list)
    service_uuids: list[str] = field(default_factory=list)
    service_names: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    #: Bytes we could not attribute to any known AD structure.
    trailing: bytes = b""
    parse_errors: list[str] = field(default_factory=list)

    @property
    def decodings(self) -> list[Decoding]:
        return [d for s in self.structures for d in s.decodings]

    @property
    def protocols(self) -> list[str]:
        seen: dict[str, None] = {}
        for d in self.decodings:
            seen[d.protocol] = None
        return list(seen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "advertisement": self.advertisement.to_dict(),
            "structures": [s.to_dict() for s in self.structures],
            "local_name": self.local_name,
            "tx_power": self.tx_power,
            "appearance": self.appearance,
            "appearance_name": self.appearance_name,
            "company_ids": self.company_ids,
            "company_names": self.company_names,
            "service_uuids": self.service_uuids,
            "service_names": self.service_names,
            "flags": self.flags,
            "trailing": self.trailing.hex(),
            "parse_errors": self.parse_errors,
            "protocols": self.protocols,
        }


# ---------------------------------------------------------------------------
# Identification
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Evidence:
    """One concrete observation supporting a guess.

    Every guess must be able to show its work. ``observation`` is what we saw,
    verbatim enough that the user can check it themselves.
    """

    observation: str
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Guess:
    label: str
    confidence: Confidence
    evidence: list[Evidence] = field(default_factory=list)
    category: Category = Category.UNKNOWN
    vendor: str | None = None
    #: Which matcher produced this, for debugging and for plugin attribution.
    matcher: str = ""
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "confidence": self.confidence.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "category": self.category.value,
            "vendor": self.vendor,
            "matcher": self.matcher,
            "score": round(self.score, 4),
        }


@dataclass(slots=True)
class Identification:
    """Ranked guesses for one device. The top one is never stated as fact."""

    best: Guess | None
    runners_up: list[Guess] = field(default_factory=list)
    #: A user-supplied label always wins and is marked as such.
    user_label: str | None = None

    @property
    def display_label(self) -> str:
        if self.user_label:
            return self.user_label
        if self.best:
            return self.best.label
        return "Unidentified device"

    @property
    def category(self) -> Category:
        if self.best:
            return self.best.category
        return Category.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "best": self.best.to_dict() if self.best else None,
            "runners_up": [g.to_dict() for g in self.runners_up],
            "user_label": self.user_label,
            "display_label": self.display_label,
            "category": self.category.value,
            "is_guess": self.user_label is None,
        }


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Capabilities:
    """What a capture backend can and cannot observe.

    Every backend declares this honestly, and the UI and ``blemon doctor``
    render it verbatim. Nothing above the capture layer may assume a capability
    that was not declared here.
    """

    name: str
    description: str = ""
    #: Legacy advertising on 37/38/39.
    advertising: bool = True
    #: BT5 extended advertising / secondary channels.
    extended_advertising: bool = False
    #: Real hardware addresses rather than opaque per-app identifiers.
    real_mac_addresses: bool = True
    #: Complete unfiltered AD payloads.
    raw_payloads: bool = True
    #: Scan responses delivered as distinct events.
    scan_responses: bool = True
    #: Can follow a connection and see data-channel PDUs.
    connection_following: bool = False
    #: Can listen on all three primary advertising channels at once.
    three_channel_advertising: bool = False
    #: Non-1M PHYs.
    coded_phy: bool = False
    two_m_phy: bool = False
    #: Can transmit at all (probing, active scan). Receive-only backends say no.
    can_transmit: bool = False
    #: Per-packet channel number is reported.
    channel_reporting: bool = False
    #: Honest, human-readable caveats shown next to the capability table.
    caveats: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def missing(self) -> list[str]:
        """Capabilities this backend lacks, as user-facing phrases."""
        out = []
        if not self.real_mac_addresses:
            out.append("real MAC addresses")
        if not self.extended_advertising:
            out.append("BT5 extended advertising")
        if not self.connection_following:
            out.append("connection following (what devices say once paired)")
        if not self.three_channel_advertising:
            out.append("simultaneous 37/38/39 capture")
        if not self.coded_phy:
            out.append("long-range Coded PHY")
        if not self.channel_reporting:
            out.append("per-packet channel numbers")
        return out
