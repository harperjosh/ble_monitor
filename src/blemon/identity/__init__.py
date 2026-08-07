"""Identification: turning observations into ranked, evidenced guesses.

Importing this package registers the bundled matchers.
"""

from __future__ import annotations

from blemon.identity import matchers  # noqa: F401  (registers matchers)
from blemon.identity.continuity import (
    Link,
    apply_links,
    explain_absence,
    find_links,
    fingerprint,
)
from blemon.identity.engine import identify, matcher, registered_matchers
from blemon.identity.trackers import Alert, AlertLevel, evaluate_all

__all__ = [
    "identify",
    "matcher",
    "registered_matchers",
    "fingerprint",
    "find_links",
    "apply_links",
    "explain_absence",
    "Link",
    "Alert",
    "AlertLevel",
    "evaluate_all",
]
