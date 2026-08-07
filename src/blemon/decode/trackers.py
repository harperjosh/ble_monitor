"""Consumer item trackers: Tile, Samsung SmartTag, Chipolo and friends.

Apple's Find My and Google's Find My Device Network are handled in
``apple.py`` and ``eddystone.py`` respectively, because they ride on those
ecosystems' framing. This module covers the rest.

Everything here sets the ``tracker`` tag, which is what the tracker-awareness
alerting in ``identity/trackers.py`` keys off.
"""

from __future__ import annotations

from typing import Any

from blemon.decode.registry import manufacturer_decoder, service_data_decoder
from blemon.models import Category, Decoding, Field_

TILE_UUID = "FEED"
TILE_ACTIVATION_UUID = "FEEC"
SAMSUNG_SMARTTAG_UUID = "FD5A"
SAMSUNG_OFFLINE_FINDING_UUID = "FD59"
CHIPOLO_UUID = "FE33"

TILE_COMPANY_ID = 0x0157
SAMSUNG_COMPANY_ID = 0x0075
PEBBLEBEE_COMPANY_ID = 0x0C1C


@service_data_decoder(TILE_UUID, name="tile")
def decode_tile(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    fields = [Field_("payload", data.hex().upper(), 0, len(data))]
    tile_id = None
    # Tile's newer advertisements carry an 8-byte rotating identifier after a
    # two-byte header; older ones put the raw Tile ID straight in.
    if len(data) >= 10:
        tile_id = data[2:10].hex().upper()
        fields.append(
            Field_("tile_id", tile_id, 2, 8, "rotating identifier in current firmware")
        )
    elif len(data) >= 8:
        tile_id = data[:8].hex().upper()
        fields.append(Field_("tile_id", tile_id, 0, 8))
    return [
        Decoding(
            protocol="tile",
            summary=f"Tile tracker{f' {tile_id}' if tile_id else ''}",
            fields=fields,
            english=(
                "This is a Tile tracker — a keyring or wallet tag. It advertises constantly "
                "so that any phone running the Tile app can report where it saw it. "
                "If you do not own a Tile and one is consistently near you across separate "
                "sessions, that is worth a second look."
            ),
            category=Category.TRACKER,
            tags=["tile", "tracker"],
        )
    ]


@service_data_decoder(TILE_ACTIVATION_UUID, name="tile_activation")
def decode_tile_activation(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    return [
        Decoding(
            protocol="tile",
            summary="Tile in activation / pairing mode",
            fields=[Field_("payload", data.hex().upper(), 0, len(data))],
            english=(
                "A Tile tracker that has not been paired yet, or has been put back into "
                "pairing mode. Somebody nearby is setting one up right now."
            ),
            category=Category.TRACKER,
            tags=["tile", "tracker", "pairing_mode"],
        )
    ]


@service_data_decoder(SAMSUNG_SMARTTAG_UUID, name="samsung_smarttag")
def decode_samsung_smarttag(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    fields = [Field_("payload", data.hex().upper(), 0, len(data))]
    if len(data) >= 4:
        fields.append(Field_("service_id", data[:2].hex().upper(), 0, 2))
        fields.append(
            Field_("rotating_id", data[2:].hex().upper(), 2, len(data) - 2, "changes periodically")
        )
    return [
        Decoding(
            protocol="samsung_smarttag",
            summary="Samsung SmartTag / SmartThings Find",
            fields=fields,
            english=(
                "A Samsung SmartTag, or a Galaxy device participating in SmartThings Find. "
                "It broadcasts a rotating identifier that nearby Galaxy phones relay back to "
                "Samsung so the owner can locate it. Like Apple's Find My, the rotation means "
                "you cannot follow it yourself — but it is a findable object in the room."
            ),
            category=Category.TRACKER,
            tags=["samsung", "smarttag", "tracker", "rotating_identity"],
        )
    ]


@service_data_decoder(SAMSUNG_OFFLINE_FINDING_UUID, name="samsung_offline_finding")
def decode_samsung_offline(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    return [
        Decoding(
            protocol="samsung_offline_finding",
            summary="Samsung offline finding beacon",
            fields=[Field_("payload", data.hex().upper(), 0, len(data))],
            english=(
                "A Samsung device in offline-finding mode — separated from its owner and "
                "relying on other Galaxy phones to report its position."
            ),
            category=Category.TRACKER,
            tags=["samsung", "tracker", "rotating_identity", "separated_tracker"],
        )
    ]


@service_data_decoder(CHIPOLO_UUID, name="chipolo")
def decode_chipolo(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    return [
        Decoding(
            protocol="chipolo",
            summary="Chipolo tracker",
            fields=[Field_("payload", data.hex().upper(), 0, len(data))],
            english=(
                "A Chipolo item tracker in its own (non-Find My) mode. Newer Chipolo models "
                "ride on Apple's Find My or Google's network instead and will show up as "
                "those instead of this."
            ),
            category=Category.TRACKER,
            tags=["chipolo", "tracker"],
        )
    ]


@manufacturer_decoder(TILE_COMPANY_ID, name="tile_mfg")
def decode_tile_mfg(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    return [
        Decoding(
            protocol="tile",
            summary=f"Tile manufacturer data, {len(data)} bytes",
            fields=[Field_("payload", data.hex().upper(), 0, len(data))],
            english="A Tile tracker, identified by its registered company ID rather than "
            "by service data.",
            category=Category.TRACKER,
            tags=["tile", "tracker"],
        )
    ]


@manufacturer_decoder(PEBBLEBEE_COMPANY_ID, name="pebblebee")
def decode_pebblebee(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    return [
        Decoding(
            protocol="pebblebee",
            summary=f"PebbleBee tracker, {len(data)} bytes",
            fields=[Field_("payload", data.hex().upper(), 0, len(data))],
            english="A PebbleBee item tracker. These also participate in Apple's and "
            "Google's finding networks depending on how they were set up.",
            category=Category.TRACKER,
            tags=["pebblebee", "tracker"],
        )
    ]
