"""Structured hex view with byte volatility.

For payloads no decoder recognises, the single most informative thing we can
show is *which bytes change between advertisements and which do not*. A stable
region is an identifier; a region that changes every packet is a counter, a
nonce or a sensor reading; a region that changes every few minutes is a rotating
token. That distinction alone reveals a great deal about an unknown device
without knowing anything about its protocol.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ByteProfile:
    offset: int
    #: Most recently seen value.
    value: int
    #: Distinct values seen at this offset across the sample window.
    distinct: int
    #: 0.0 = never changed, 1.0 = different in every observation.
    volatility: float
    classification: str  # stable | slow | counter | volatile

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "value": self.value,
            "hex": f"{self.value:02x}",
            "distinct": self.distinct,
            "volatility": round(self.volatility, 3),
            "classification": self.classification,
        }


def _classify(distinct: int, samples: int, monotonic: bool) -> str:
    if distinct <= 1:
        return "stable"
    if monotonic and distinct > 2:
        return "counter"
    ratio = (distinct - 1) / max(1, samples - 1)
    if ratio >= 0.8:
        return "volatile"
    return "slow"


def profile_bytes(payloads: list[bytes]) -> list[ByteProfile]:
    """Profile each byte offset across a window of payloads from one device.

    ``payloads`` should be ordered oldest to newest. Payloads of differing
    length are handled by only profiling offsets present in all of them.
    """
    if not payloads:
        return []
    width = min(len(p) for p in payloads)
    samples = len(payloads)
    out: list[ByteProfile] = []
    for off in range(width):
        column = [p[off] for p in payloads]
        counts = Counter(column)
        distinct = len(counts)
        # A counter byte increases (allowing for a single 8-bit wrap).
        rises = sum(
            1 for a, b in zip(column, column[1:], strict=False) if b == (a + 1) % 256 or (b > a and b - a < 8)
        )
        monotonic = samples > 2 and rises >= (samples - 1) * 0.7
        out.append(
            ByteProfile(
                offset=off,
                value=column[-1],
                distinct=distinct,
                volatility=(distinct - 1) / max(1, samples - 1),
                classification=_classify(distinct, samples, monotonic),
            )
        )
    return out


def hexdump(data: bytes, width: int = 16) -> list[dict[str, Any]]:
    """Rows of ``{offset, hex, ascii}`` for a classic offset-annotated dump."""
    rows = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        rows.append(
            {
                "offset": i,
                "hex": " ".join(f"{b:02x}" for b in chunk),
                "ascii": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk),
                "bytes": list(chunk),
            }
        )
    return rows


def summarize_volatility(profiles: list[ByteProfile]) -> str:
    """One sentence of plain English about an unknown payload's shape."""
    if not profiles:
        return "Not enough observations yet to say which bytes change."
    stable = [p for p in profiles if p.classification == "stable"]
    counters = [p for p in profiles if p.classification == "counter"]
    volatile = [p for p in profiles if p.classification == "volatile"]

    parts = []
    if stable:
        parts.append(
            f"{len(stable)} of {len(profiles)} bytes never change — that fixed part is "
            "effectively an identifier for this device"
        )
    if counters:
        offs = ", ".join(str(p.offset) for p in counters[:4])
        parts.append(f"byte{'s' if len(counters) > 1 else ''} {offs} count steadily upward")
    if volatile:
        parts.append(
            f"{len(volatile)} bytes change on nearly every packet, which usually means a "
            "nonce, an encrypted field or a live measurement"
        )
    if not parts:
        return "The payload changes slowly and does not have an obvious fixed identifier."
    return "; ".join(parts).capitalize() + "."
