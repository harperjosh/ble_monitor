"""A synthetic radio environment.

This exists for three reasons and all three matter:

1. You can see what the tool does before any hardware arrives.
2. Every view, the CLI and the API can be exercised in CI with no radio.
3. When a real capture shows nothing, running against this tells you instantly
   whether the problem is the radio or the software.

It is labelled as synthetic everywhere it surfaces. Nothing here is ever
presented as a real observation.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import AsyncIterator

from blemon.capture.base import BackendStatus, CaptureBackend, Event, register
from blemon.fixtures import advertisement_from, default_population
from blemon.models import Capabilities


class SyntheticBackend(CaptureBackend):
    name = "synthetic"

    def __init__(self, speed: float = 1.0, seed: int = 1, **_: object) -> None:
        super().__init__()
        self.speed = max(0.05, speed)
        self._rng = random.Random(seed)
        self._population = default_population()
        self._t0 = time.time()

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(
            name="Synthetic environment",
            description="A simulated café: phones, earbuds, trackers, beacons and sensors.",
            advertising=True,
            extended_advertising=False,
            real_mac_addresses=True,
            raw_payloads=True,
            scan_responses=False,
            connection_following=False,
            three_channel_advertising=True,
            coded_phy=False,
            two_m_phy=False,
            can_transmit=False,
            channel_reporting=True,
            caveats=[
                "This is not a radio. Every device shown here is generated locally and "
                "none of it is real.",
                "Payload formats are faithful to the real protocols, so decoding and "
                "identification behave exactly as they would on live traffic.",
            ],
        )

    @staticmethod
    def available() -> tuple[bool, str]:
        return True, ""

    async def start(self) -> None:
        await super().start()
        self._t0 = time.time()
        self._status = BackendStatus(
            "running",
            "Generating a simulated environment — no radio is in use.",
            {"devices": len(self._population), "speed": self.speed},
        )

    async def stream(self) -> AsyncIterator[Event]:
        yield self._status
        tick = 0.1
        while self.running:
            now = time.time()
            elapsed = (now - self._t0) * self.speed
            for device in self._population:
                if not (device.present_from <= elapsed <= device.present_until):
                    continue
                # Probability that this device advertised during this tick.
                if self._rng.random() > min(1.0, (tick * self.speed) / device.interval):
                    continue
                adv = advertisement_from(device, elapsed, self._rng, source="synthetic")
                adv.timestamp = now
                yield adv
            await asyncio.sleep(tick)


register("synthetic", SyntheticBackend, priority=100)
