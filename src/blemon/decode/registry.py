"""Decoder plugin registry.

A decoder is a small object that claims a slice of the advertising payload it
understands and returns a :class:`Decoding`. Adding support for a new
ecosystem protocol later means writing one class and decorating it — never
editing the parser.

Two kinds of decoder exist:

``@manufacturer_decoder(0x004C)``
    Called with the manufacturer-specific data body for that company ID.

``@service_data_decoder("FEAA")``
    Called with the service-data body for that service UUID.

``@generic_decoder``
    Called with the whole parsed advertisement, for cross-cutting inferences.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, Protocol

from blemon.models import Decoding


class PayloadDecoder(Protocol):
    """Callable taking (data, context) and returning zero or more decodings."""

    def __call__(self, data: bytes, context: dict[str, Any]) -> Iterable[Decoding]: ...


_MANUFACTURER: dict[int, list[tuple[str, PayloadDecoder]]] = {}
_SERVICE_DATA: dict[str, list[tuple[str, PayloadDecoder]]] = {}
_GENERIC: list[tuple[str, Callable[[Any], Iterable[Decoding]]]] = []


def manufacturer_decoder(
    company_id: int, name: str | None = None
) -> Callable[[PayloadDecoder], PayloadDecoder]:
    def wrap(fn: PayloadDecoder) -> PayloadDecoder:
        _MANUFACTURER.setdefault(company_id, []).append((name or fn.__name__, fn))
        return fn

    return wrap


def service_data_decoder(
    uuid: str, name: str | None = None
) -> Callable[[PayloadDecoder], PayloadDecoder]:
    key = uuid.upper()

    def wrap(fn: PayloadDecoder) -> PayloadDecoder:
        _SERVICE_DATA.setdefault(key, []).append((name or fn.__name__, fn))
        return fn

    return wrap


def generic_decoder(name: str | None = None):
    def wrap(fn):
        _GENERIC.append((name or fn.__name__, fn))
        return fn

    return wrap


def _run(entries, *args) -> list[Decoding]:
    out: list[Decoding] = []
    for label, fn in entries:
        try:
            result = fn(*args)
        except Exception as exc:  # a broken decoder must never kill a capture
            out.append(
                Decoding(
                    protocol=label,
                    summary=f"decoder error: {type(exc).__name__}: {exc}",
                    english="This payload matched a decoder that then failed on it. "
                    "The raw bytes are still shown below.",
                    tags=["decoder_error"],
                )
            )
            continue
        if result:
            out.extend(result)
    return out


def decode_manufacturer(company_id: int, data: bytes, context: dict[str, Any]) -> list[Decoding]:
    return _run(_MANUFACTURER.get(company_id, []), data, context)


def decode_service_data(uuid: str, data: bytes, context: dict[str, Any]) -> list[Decoding]:
    return _run(_SERVICE_DATA.get(uuid.upper(), []), data, context)


def decode_generic(parsed) -> list[Decoding]:
    return _run(_GENERIC, parsed)


def registered() -> dict[str, list[str]]:
    """Introspection for ``blemon doctor`` and the API's /capabilities view."""
    return {
        "manufacturer": [f"0x{cid:04X}: {n}" for cid, e in _MANUFACTURER.items() for n, _ in e],
        "service_data": [f"{u}: {n}" for u, e in _SERVICE_DATA.items() for n, _ in e],
        "generic": [n for n, _ in _GENERIC],
    }
