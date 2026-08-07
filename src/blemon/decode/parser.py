"""Top-level advertisement parsing: raw bytes to a fully decoded structure."""

from __future__ import annotations

import struct

from blemon.decode import adtypes
from blemon.decode.assigned import appearance_name, company_name, service_name
from blemon.decode.registry import decode_generic, decode_manufacturer, decode_service_data
from blemon.models import Advertisement, Decoding, Field_, ParsedAdvertisement


def parse(adv: Advertisement) -> ParsedAdvertisement:
    """Parse and decode one advertisement. Never raises on malformed input."""
    parsed = ParsedAdvertisement(advertisement=adv)

    structures, trailing, errors = adtypes.split_ad_structures(adv.raw)
    parsed.trailing = trailing
    parsed.parse_errors.extend(errors)

    context = {
        "address": adv.address,
        "address_type": adv.address_type.value,
        "rssi": adv.rssi,
        "timestamp": adv.timestamp,
        "scan_response": adv.scan_response,
    }

    for offset, type_code, data in structures:
        st = adtypes.parse_structure(offset, type_code, data)

        # Roll structural fields up to the advertisement level for easy access.
        for fld in st.fields:
            if fld.name == "local_name" and not parsed.local_name:
                parsed.local_name = str(fld.value)
            elif fld.name == "tx_power":
                parsed.tx_power = int(fld.value)
            elif fld.name == "appearance":
                parsed.appearance = int(fld.value)
                parsed.appearance_name = appearance_name(int(fld.value))
            elif fld.name == "flags":
                parsed.flags = list(fld.value)
            elif fld.name == "service_uuid":
                uuid = str(fld.value)
                if uuid not in parsed.service_uuids:
                    parsed.service_uuids.append(uuid)
                    parsed.service_names.append(service_name(uuid) or "")
            elif fld.name == "company_id":
                cid = int(fld.value)
                if cid not in parsed.company_ids:
                    parsed.company_ids.append(cid)
                    parsed.company_names.append(company_name(cid) or f"unregistered 0x{cid:04X}")

        # Run protocol decoders over the structure's body.
        if type_code == 0xFF and len(data) >= 2:
            cid = struct.unpack("<H", data[:2])[0]
            st.decodings.extend(decode_manufacturer(cid, data[2:], context))
            if not st.decodings:
                st.decodings.append(_undecoded_manufacturer(cid, data[2:]))
        elif type_code in (0x16, 0x20, 0x21):
            uuid = adtypes.service_uuid_of(st)
            body = adtypes.service_data_body(st)
            if uuid:
                st.decodings.extend(decode_service_data(uuid, body, context))
                if not st.decodings:
                    st.decodings.append(_undecoded_service_data(uuid, body))

        parsed.structures.append(st)

    for extra in decode_generic(parsed):
        if parsed.structures:
            parsed.structures[-1].decodings.append(extra)

    return parsed


def _undecoded_manufacturer(company_id: int, body: bytes) -> Decoding:
    name = company_name(company_id)
    who = name or f"an unregistered company ID (0x{company_id:04X})"
    return Decoding(
        protocol="manufacturer_data",
        summary=f"Manufacturer data from {who}, {len(body)} bytes",
        fields=[
            Field_("company_id", f"0x{company_id:04X}", 0, 2, name or "unregistered"),
            Field_("payload", body.hex(), 2, len(body)),
        ],
        english=(
            f"This device is broadcasting {len(body)} bytes of vendor-private data registered "
            f"to {who}. There is no public specification for it, so we can tell you who made "
            "the device but not what it is saying. The byte-level view will show you which "
            "parts of it stay fixed and which change — that is usually enough to tell an "
            "identifier from a counter."
        ),
        tags=["undecoded", "vendor_private"],
    )


def _undecoded_service_data(uuid: str, body: bytes) -> Decoding:
    name = service_name(uuid)
    return Decoding(
        protocol="service_data",
        summary=f"Service data for {uuid}"
        + (f" ({name})" if name else "")
        + f", {len(body)} bytes",
        fields=[
            Field_("service_uuid", uuid, 0, None, name or "not in our local tables"),
            Field_("payload", body.hex(), None, len(body)),
        ],
        english=(
            f"Service data attached to UUID {uuid}"
            + (f", which is registered as {name}. " if name else ". ")
            + "We do not have a decoder for this particular payload, so the bytes are shown "
            "raw and profiled for which of them change over time."
        ),
        tags=["undecoded"],
    )
