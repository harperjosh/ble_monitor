"""Replay a recorded session through the live views.

Playing a capture back at adjustable speed is the difference between "I have a
database" and "I can watch what happened in the airport at 6am". It uses the
same event stream as a live radio, so every view works unchanged.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator

from blemon.capture.base import BackendStatus, CaptureBackend, CaptureError, Event, register
from blemon.models import Capabilities
from blemon.store import Store


class ReplayBackend(CaptureBackend):
    name = "replay"

    def __init__(
        self,
        session_id: int,
        store: Store | None = None,
        speed: float = 1.0,
        loop: bool = False,
        db_path: str | None = None,
        **_: object,
    ) -> None:
        super().__init__()
        self.store = store or Store(db_path)
        self.session_id = int(session_id)
        self.speed = max(0.05, float(speed))
        self.loop = loop
        session = self.store.session(self.session_id)
        if session is None:
            raise CaptureError(
                f"No recorded session with id {session_id}.",
                remedy="Run `blemon sessions` to list what is stored.",
            )
        self._session = session
        self._recorded_caps = session.get("capabilities") or {}

    @property
    def capabilities(self) -> Capabilities:
        # Replay can never show more than the capture that produced it, so we
        # report the original backend's capabilities rather than our own.
        caps = Capabilities(
            name=f"Replay of “{self._session['name']}”",
            description=(
                f"Recorded {time.strftime('%Y-%m-%d %H:%M', time.localtime(self._session['started_at']))}"
                f" by the {self._session.get('backend') or 'unknown'} backend."
            ),
        )
        for field_name, value in self._recorded_caps.items():
            if hasattr(caps, field_name) and field_name not in ("name", "description", "caveats"):
                setattr(caps, field_name, value)
        caps.can_transmit = False
        caps.caveats = list(self._recorded_caps.get("caveats", [])) + [
            "This is recorded data being played back. Nothing here is live, and the "
            "capabilities shown are those of the backend that recorded it.",
        ]
        return caps

    @staticmethod
    def available() -> tuple[bool, str]:
        return False, "replay must be given a session id explicitly"

    async def start(self) -> None:
        await super().start()
        self._status = BackendStatus(
            "replaying",
            f"Replaying session {self.session_id} at {self.speed}x.",
            {"session_id": self.session_id, "speed": self.speed},
        )

    async def stream(self) -> AsyncIterator[Event]:
        yield self._status
        while self.running:
            first_ts: float | None = None
            wall_start = time.time()
            count = 0
            for _key, adv in self.store.replay(self.session_id):
                if not self.running:
                    return
                if first_ts is None:
                    first_ts = adv.timestamp
                target = (adv.timestamp - first_ts) / self.speed
                drift = target - (time.time() - wall_start)
                if drift > 0.002:
                    await asyncio.sleep(min(drift, 2.0))
                # Present replayed packets on the current clock so every
                # rate and duration calculation downstream stays correct.
                adv.timestamp = time.time()
                adv.source = f"replay:{self.session_id}"
                count += 1
                yield adv
                if count % 500 == 0:
                    await asyncio.sleep(0)  # let the event loop breathe
            yield BackendStatus(
                "finished",
                f"Replay of session {self.session_id} complete ({count} packets).",
                {"session_id": self.session_id, "packets": count},
            )
            if not self.loop:
                return
            await asyncio.sleep(1.0)


register("replay", ReplayBackend, priority=90)
