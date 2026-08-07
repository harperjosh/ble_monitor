"""Capture: radio access, behind one interface with honest capability reporting.

Importing this package registers every bundled backend. Registration order sets
autoselect preference: a sniffer sees the most, then the host adapter, then the
synthetic environment so the tool is never simply blank.
"""

from __future__ import annotations

from blemon.capture import (  # noqa: F401  (registration side effects)
    bleak_backend,
    hci_linux,
    nrf_sniffer,
    replay,
    sniffle,
    synthetic,
)
from blemon.capture.base import (
    BackendStatus,
    Capabilities,
    CaptureBackend,
    CaptureError,
    Event,
    autoselect,
    available_backends,
    create,
    register,
)

__all__ = [
    "CaptureBackend",
    "CaptureError",
    "BackendStatus",
    "Capabilities",
    "Event",
    "create",
    "autoselect",
    "available_backends",
    "register",
]
