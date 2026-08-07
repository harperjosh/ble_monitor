"""Decoding: raw advertising bytes to structured, named, explained fields.

Importing this package registers every bundled protocol decoder. Third-party
decoders register the same way — import the module and the decorators in
``blemon.decode.registry`` do the rest.
"""

from __future__ import annotations

from blemon.decode import apple, eddystone, fastpair, microsoft, sensors, trackers  # noqa: F401
from blemon.decode.parser import parse
from blemon.decode.registry import registered

__all__ = ["parse", "registered"]
