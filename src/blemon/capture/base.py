"""The capture-source abstraction.

Every backend implements the same small interface and **declares its own
capabilities**. That declaration is not decoration: the UI and ``blemon doctor``
render it verbatim, and no layer above capture is allowed to assume a
capability that was not declared. This is what stops the tool from quietly
implying it can see connection traffic when it is running off a laptop's
built-in adapter.

A backend is an async iterator of events. It may yield:

* :class:`~blemon.models.Advertisement` — a received advertising packet
* :class:`~blemon.models.LinkEvent` — a connection-layer event (sniffers only)
* :class:`BackendStatus` — a change in what the backend is doing, so the UI can
  say "following a connection on channel 12" rather than going quiet
"""

from __future__ import annotations

import abc
import asyncio
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

from blemon.models import AddressType, Advertisement, Capabilities, LinkEvent


@dataclass
class BackendStatus:
    """A state change worth telling the user about."""

    state: str
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state, "detail": self.detail, "data": self.data}


Event = Advertisement | LinkEvent | BackendStatus


class CaptureError(RuntimeError):
    """A backend could not start, with an explanation a human can act on.

    ``remedy`` is the important field: an error that says "permission denied"
    and stops is useless, one that says which command grants the capability is
    not.
    """

    def __init__(self, message: str, remedy: str = ""):
        super().__init__(message)
        self.remedy = remedy


class CaptureBackend(abc.ABC):
    """Base class for every capture source."""

    #: Short stable identifier, e.g. "hci", "bleak", "sniffle".
    name: str = "backend"

    def __init__(self) -> None:
        self._running = False
        self._status = BackendStatus("idle")

    # -- required ----------------------------------------------------------

    @property
    @abc.abstractmethod
    def capabilities(self) -> Capabilities:
        """What this backend can and cannot observe. Must be honest."""

    @abc.abstractmethod
    def stream(self) -> AsyncIterator[Event]:
        """Yield events until stopped. Must not raise on transient errors."""

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    # -- optional ----------------------------------------------------------

    async def follow(
        self, address: str, address_type: AddressType | str | None = None
    ) -> bool:
        """Aim connection-following at one device. False if unsupported.

        ``address_type`` is the device's known address type when the caller has
        it; some sniffers need it to build the correct connection-follow filter.
        None means "not known" — which is a real answer, not a prompt to guess:
        the type cannot be recovered from the address bits.
        """
        return False

    async def unfollow(self) -> None:
        return None

    @property
    def status(self) -> BackendStatus:
        return self._status

    def describe(self) -> dict[str, Any]:
        caps = self.capabilities
        return {
            "name": self.name,
            "capabilities": caps.to_dict(),
            "missing": caps.missing(),
            "status": self.status.to_dict(),
            "running": self.running,
        }

    @staticmethod
    def available() -> tuple[bool, str]:
        """Whether this backend could run here, and why not if it cannot."""
        return True, ""


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_BACKENDS: dict[str, Callable[..., CaptureBackend]] = {}
_PRIORITY: dict[str, int] = {}


def register(name: str, factory: Callable[..., CaptureBackend], priority: int = 50) -> None:
    """Register a backend. Lower ``priority`` is tried first by ``autoselect``.

    The ordering encodes how much each backend can actually see: a sniffer
    beats a host adapter, a raw HCI socket beats going through the OS stack,
    and the synthetic environment is the last resort so the tool is never
    simply blank.
    """
    _BACKENDS[name] = factory
    _PRIORITY[name] = priority


def _ordered() -> list[str]:
    return sorted(_BACKENDS, key=lambda n: (_PRIORITY.get(n, 50), n))


def available_backends() -> dict[str, str]:
    """Backend name to reason-it-cannot-run (empty string means it can)."""
    out: dict[str, str] = {}
    for name in _ordered():
        factory = _BACKENDS[name]
        checker = getattr(factory, "available", None)
        if checker is None:
            cls = getattr(factory, "__self__", None) or factory
            checker = getattr(cls, "available", None)
        try:
            ok, why = checker() if checker else (True, "")
        except Exception as exc:  # a probe must never crash the listing
            ok, why = False, f"probe failed: {exc}"
        out[name] = "" if ok else why
    return out


def create(name: str, **kwargs: Any) -> CaptureBackend:
    if name not in _BACKENDS:
        known = ", ".join(_ordered()) or "none registered"
        raise CaptureError(
            f"Unknown capture backend {name!r}.",
            remedy=f"Available backends: {known}. Run `blemon doctor` for details.",
        )
    return _BACKENDS[name](**kwargs)


def autoselect(**kwargs: Any) -> CaptureBackend:
    """Pick the most capable backend that can actually run here.

    Order is: an attached sniffer (it sees the most), then the host adapter,
    then the synthetic environment so the tool is never simply blank.
    """
    reasons = available_backends()
    for name in _ordered():
        if reasons.get(name) == "":
            try:
                return create(name, **kwargs)
            except CaptureError:
                continue
    raise CaptureError(
        "No capture backend can run on this machine.",
        remedy="Run `blemon doctor` — it will say exactly what is missing and how to fix it. "
        "`blemon scan --backend synthetic` always works and shows you what the tool does.",
    )


# ---------------------------------------------------------------------------
# Helpers shared by backends
# ---------------------------------------------------------------------------


class QueueBackend(CaptureBackend):
    """Convenience base for backends that push events from a thread or callback."""

    def __init__(self, maxsize: int = 4096) -> None:
        super().__init__()
        self._queue: asyncio.Queue[Event | None] = asyncio.Queue(maxsize=maxsize)
        self._dropped = 0

    def emit(self, event: Event) -> None:
        """Non-blocking push. Drops rather than stalls the radio thread.

        A dense RF environment can out-produce a slow consumer, and blocking a
        capture thread is worse than losing a packet — so we count what we lost
        and say so, rather than pretending the count is complete.
        """
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._dropped += 1

    def emit_threadsafe(self, loop: asyncio.AbstractEventLoop, event: Event) -> None:
        loop.call_soon_threadsafe(self.emit, event)

    @property
    def dropped(self) -> int:
        return self._dropped

    async def stop(self) -> None:
        await super().stop()
        try:
            self._queue.put_nowait(None)
        except asyncio.QueueFull:
            pass

    async def stream(self) -> AsyncIterator[Event]:
        # Emit the post-start status first so the UI shows what the backend is
        # doing immediately. Every QueueBackend subclass wants this, so it lives
        # here rather than being copy-pasted into each one's stream() override.
        yield self._status
        while self.running:
            event = await self._queue.get()
            if event is None:
                break
            yield event
