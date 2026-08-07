"""Google Fast Pair (service UUID 0xFE2C).

Fast Pair is what makes an Android phone pop up "Pixel Buds — connect?" when
you open a case. It has two modes with very different privacy properties, and
telling them apart is genuinely useful.
"""

from __future__ import annotations

from typing import Any

from blemon.decode.registry import service_data_decoder
from blemon.models import Category, Decoding, Field_

FAST_PAIR_UUID = "FE2C"

#: A small, deliberately partial table. Google's model-ID registry is not
#: published as a bulk download, so we resolve the handful that are widely
#: documented and show the raw ID for everything else rather than inventing
#: a name.
KNOWN_MODELS: dict[int, str] = {
    0x0001F0: "Google Pixel Buds",
    0x00000D: "Google Pixel Buds (2020)",
    0x00B727: "Sony WH-1000XM3",
    0x0201F9: "Sony WF-1000XM3",
    0x02AA91: "Sony WH-1000XM4",
    0x0002F0: "Google Pixel Buds A-Series",
    0x821F66: "JBL Live Pro 2",
    0x038B29: "Bose QuietComfort",
    0x2D7A23: "Sony WF-1000XM4",
    0x0E30C3: "Jabra Elite",
}

FIELD_TYPES = {
    0x0: "account key filter",
    0x1: "account key filter (with UI indication)",
    0x2: "salt",
    0x3: "battery",
    0x4: "battery (with UI indication)",
    0x5: "random resolvable data",
}


@service_data_decoder(FAST_PAIR_UUID, name="fast_pair")
def decode_fast_pair(data: bytes, context: dict[str, Any]) -> list[Decoding]:
    if not data:
        return []

    # Discoverable mode: exactly a 3-byte big-endian model ID.
    if len(data) == 3:
        model = int.from_bytes(data, "big")
        name = KNOWN_MODELS.get(model)
        return [
            Decoding(
                protocol="fast_pair",
                summary=f"Fast Pair discoverable, model 0x{model:06X}"
                + (f" ({name})" if name else ""),
                fields=[
                    Field_(
                        "model_id",
                        f"0x{model:06X}",
                        0,
                        3,
                        name or "not in our local model table",
                    )
                ],
                english=(
                    "A Fast Pair accessory is in pairing mode right now — somebody has just "
                    "opened a charging case or held down a pairing button. "
                    + (
                        f"The model ID identifies it as a {name}. "
                        if name
                        else "The model ID is broadcast in the clear but is not in our local "
                        "table, so we are not going to guess what it is. "
                    )
                    + "In this mode the accessory is announcing exactly what product it is "
                    "to everyone in range."
                ),
                category=Category.AUDIO,
                tags=["fast_pair", "google", "pairing_mode", "plaintext_identity"],
            )
        ]

    # Non-discoverable mode: a version/flags byte then length-tagged fields.
    version = data[0] >> 4
    flags = data[0] & 0x0F
    fields = [
        Field_("version", version, 0, 1),
        Field_("flags", f"0x{flags:X}", 0, 1),
    ]
    parts: list[str] = []
    battery_note = ""
    i = 1
    while i < len(data):
        header = data[i]
        length = header >> 4
        ftype = header & 0x0F
        body = data[i + 1 : i + 1 + length]
        tname = FIELD_TYPES.get(ftype, f"unknown field type 0x{ftype:X}")
        fields.append(Field_(tname.replace(" ", "_"), body.hex().upper(), i + 1, length))
        parts.append(tname)
        if ftype in (0x3, 0x4) and body:
            levels = []
            for b in body:
                charging = bool(b & 0x80)
                pct = b & 0x7F
                levels.append("unknown" if pct == 0x7F else f"{pct}%{' charging' if charging else ''}")
            fields.append(Field_("battery_levels", levels, i + 1, length))
            battery_note = " It is also broadcasting its battery levels: " + ", ".join(levels) + "."
        i += 1 + length
        if length == 0:
            break

    return [
        Decoding(
            protocol="fast_pair",
            summary=f"Fast Pair non-discoverable (v{version}), fields: {', '.join(parts) or 'none'}",
            fields=fields,
            english=(
                "A Fast Pair accessory that is already paired with somebody. Instead of its "
                "model ID it broadcasts an 'account key filter' — a bloom filter that only "
                "its owner's phone can match. To you it is an opaque, rotating token, which "
                "is the privacy-preserving half of the design." + battery_note
            ),
            category=Category.AUDIO,
            tags=["fast_pair", "google", "rotating_identity"]
            + (["battery_leak"] if battery_note else []),
        )
    ]
