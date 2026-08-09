"""Tracker awareness.

Two related jobs:

1. Recognise known tracker hardware on sight — AirTag, Tile, SmartTag, Chipolo,
   PebbleBee, Google's Find My Device tags.
2. Raise an alert when an *unknown* device with a rotating address persists near
   you across a long window, or turns up again in a later session.

Rule 2 is the defensive case and it is the one that has to be built carefully:
an alert with no explanation is just anxiety. Every alert carries the concrete
observations behind it and a plain statement of what would make it a false
positive, because in a café or on a train most of them are.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from blemon.device import Device


class AlertLevel(str, Enum):
    INFO = "info"
    NOTABLE = "notable"
    ATTENTION = "attention"

    @property
    def rank(self) -> int:
        """Severity order, so an escalation can be told from a re-raise.

        A dismissal silences the level it was made at and anything below it; a
        higher level is new information and has to reach the user again.
        """
        return _LEVEL_RANK[self]


_LEVEL_RANK = {AlertLevel.INFO: 0, AlertLevel.NOTABLE: 1, AlertLevel.ATTENTION: 2}


#: How long a tracker has to hang around before it is worth mentioning.
KNOWN_TRACKER_SECONDS = 8 * 60
#: How long an unidentified rotating device has to persist before we say anything.
UNKNOWN_PERSIST_SECONDS = 20 * 60
#: …and how many distinct addresses it has to have burned through.
UNKNOWN_MIN_ADDRESSES = 3
#: Only alert on things that are actually close. A tracker three rooms away is noise.
MIN_ALERT_RSSI = -80
#: How long a tag has to be broadcasting the separated/unwanted-tracking frame
#: before it is worth an ATTENTION alert. Any Apple device in offline-finding
#: mode emits this — a powered-off phone in a bag, an AirPods case away from its
#: owner — so firing on a single packet fills the panel with warnings about
#: devices whose owners are sitting right next to them, which is what teaches
#: people to ignore the alert that matters.
SEPARATED_TRACKER_SECONDS = 5 * 60


@dataclass
class Alert:
    key: str
    device_key: str
    level: AlertLevel
    title: str
    explanation: str
    evidence: list[str] = field(default_factory=list)
    false_positive_note: str = ""
    raised_at: float = field(default_factory=time.time)
    sessions_seen: int = 1
    acknowledged: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "device_key": self.device_key,
            "level": self.level.value,
            "title": self.title,
            "explanation": self.explanation,
            "evidence": self.evidence,
            "false_positive_note": self.false_positive_note,
            "raised_at": self.raised_at,
            "sessions_seen": self.sessions_seen,
            "acknowledged": self.acknowledged,
        }


def _duration_phrase(seconds: float) -> str:
    minutes = seconds / 60.0
    if minutes < 60:
        return f"{minutes:.0f} minutes"
    return f"{minutes / 60:.1f} hours"


def evaluate(device: Device, sessions_seen: int = 1) -> list[Alert]:
    """Alerts this one device currently justifies. Empty is the normal answer."""
    if device.is_mine:
        return []

    out: list[Alert] = []
    duration = device.duration
    rssi = device.smoothed_rssi
    close_enough = rssi is None or rssi >= MIN_ALERT_RSSI

    # -- 1. A tracker that has been separated from its owner ---------------
    if (
        "separated_tracker" in device.tags
        and close_enough
        and duration >= SEPARATED_TRACKER_SECONDS
    ):
        out.append(
            Alert(
                key=f"separated:{device.key}",
                device_key=device.key,
                level=AlertLevel.ATTENTION,
                title=f"{device.display_name} is in separated mode nearby",
                explanation=(
                    "This tracker is broadcasting the state it uses when it has been away "
                    "from its owner for a while. A tag in this state that is travelling with "
                    "you is exactly the pattern unwanted-tracking detection looks for."
                ),
                evidence=[
                    "the advertisement carries the separated / unwanted-tracking frame",
                    f"seen for {_duration_phrase(duration)}",
                    f"current signal {rssi} dBm ({device.proximity.value})",
                ],
                false_positive_note=(
                    "A tag belonging to someone sitting near you will look identical. "
                    "What matters is whether it follows you when you move."
                ),
                sessions_seen=sessions_seen,
            )
        )

    # -- 2. A known tracker that has stuck around ---------------------------
    elif device.is_tracker and duration >= KNOWN_TRACKER_SECONDS and close_enough:
        level = AlertLevel.ATTENTION if sessions_seen > 1 else AlertLevel.NOTABLE
        out.append(
            Alert(
                key=f"tracker:{device.key}",
                device_key=device.key,
                level=level,
                title=f"{device.display_name} has been near you for {_duration_phrase(duration)}",
                explanation=(
                    "This is recognisable item-tracker hardware and it has stayed within "
                    "range for a sustained period."
                    + (
                        f" It has also turned up in {sessions_seen} separate capture sessions, "
                        "which is the signal that actually matters — the same tag in different "
                        "places is very different from the same tag in one place."
                        if sessions_seen > 1
                        else ""
                    )
                ),
                evidence=[
                    f"identified as {device.display_name}",
                    f"tracker protocols observed: {', '.join(sorted(device.protocols)) or 'n/a'}",
                    f"continuously present for {_duration_phrase(duration)}",
                    f"current signal {rssi} dBm ({device.proximity.value})",
                ],
                false_positive_note=(
                    "Your own tags, and anything belonging to a person you are with, will "
                    "trigger this. Mark them as yours and they will stop."
                ),
                sessions_seen=sessions_seen,
            )
        )

    # -- 3. An unidentified rotating device that will not go away -----------
    if (
        not device.is_tracker
        and device.rotates_address
        and duration >= UNKNOWN_PERSIST_SECONDS
        and len(device.addresses_seen) >= UNKNOWN_MIN_ADDRESSES
        and close_enough
        and device.category.value == "unknown"
    ):
        out.append(
            Alert(
                key=f"persistent:{device.key}",
                device_key=device.key,
                level=AlertLevel.NOTABLE if sessions_seen == 1 else AlertLevel.ATTENTION,
                title=f"An unidentified device has been near you for {_duration_phrase(duration)}",
                explanation=(
                    "This device rotates its address the way a privacy-conscious device "
                    "should, but we were able to correlate it across "
                    f"{len(device.addresses_seen)} addresses because its payload is "
                    "distinctive. It has stayed in range the whole time and we cannot tell "
                    "what it is."
                ),
                evidence=[
                    f"seen under {len(device.addresses_seen)} different addresses",
                    f"correlation confidence {device.continuity_confidence:.0%}",
                    *device.continuity_evidence[:4],
                    f"present for {_duration_phrase(duration)}",
                    f"current signal {rssi} dBm ({device.proximity.value})",
                ],
                false_positive_note=(
                    "In a fixed place — your home, an office — this is almost always a "
                    "neighbour's device or your own. It is worth attention when it appears "
                    "in several different places."
                ),
                sessions_seen=sessions_seen,
            )
        )

    return out


def evaluate_all(
    devices: list[Device],
    session_counts: dict[str, int] | None = None,
) -> list[Alert]:
    session_counts = session_counts or {}
    alerts: list[Alert] = []
    for d in devices:
        alerts.extend(evaluate(d, sessions_seen=session_counts.get(d.key, 1)))
    order = {AlertLevel.ATTENTION: 0, AlertLevel.NOTABLE: 1, AlertLevel.INFO: 2}
    alerts.sort(key=lambda a: (order[a.level], -a.sessions_seen, -a.raised_at))
    return alerts
