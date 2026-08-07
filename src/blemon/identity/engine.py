"""Identification engine.

The rule of this module, and the reason it is structured the way it is:
**an inference is never presented as a fact.** Every matcher must return a
label, a confidence, and the concrete observations that led to it. The engine
aggregates competing guesses into a ranked list and keeps the runners-up, so
the UI can always show what else it might be and why.

Adding a matcher is one decorated function. Nothing else changes.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

from blemon.models import Category, Confidence, Evidence, Guess, Identification

if TYPE_CHECKING:  # pragma: no cover
    from blemon.device import Device

Matcher = Callable[["Device"], Iterable[Guess]]

_MATCHERS: list[tuple[str, Matcher]] = []


def matcher(name: str) -> Callable[[Matcher], Matcher]:
    def wrap(fn: Matcher) -> Matcher:
        _MATCHERS.append((name, fn))
        return fn

    return wrap


def registered_matchers() -> list[str]:
    return [n for n, _ in _MATCHERS]


def guess(
    label: str,
    confidence: Confidence,
    evidence: list[str] | list[Evidence],
    category: Category = Category.UNKNOWN,
    vendor: str | None = None,
) -> Guess:
    """Convenience constructor so matchers stay readable."""
    ev = [e if isinstance(e, Evidence) else Evidence(e) for e in evidence]
    return Guess(
        label=label,
        confidence=confidence,
        evidence=ev,
        category=category,
        vendor=vendor,
        score=confidence.score,
    )


def _confidence_for(score: float) -> Confidence:
    if score >= 0.9:
        return Confidence.CERTAIN
    if score >= 0.72:
        return Confidence.HIGH
    if score >= 0.48:
        return Confidence.MEDIUM
    return Confidence.LOW


def identify(device: Device) -> Identification:
    """Run every matcher and merge the results into a ranked identification."""
    collected: list[Guess] = []
    for name, fn in _MATCHERS:
        try:
            for g in fn(device) or []:
                g.matcher = name
                collected.append(g)
        except Exception as exc:  # a bad matcher must not break identification
            collected.append(
                Guess(
                    label="matcher error",
                    confidence=Confidence.LOW,
                    evidence=[Evidence(f"{name} raised {type(exc).__name__}: {exc}")],
                    matcher=name,
                    score=0.0,
                )
            )

    merged: dict[str, Guess] = {}
    for g in collected:
        if g.label == "matcher error":
            continue
        existing = merged.get(g.label)
        if existing is None:
            merged[g.label] = g
            continue
        # Corroboration from an independent matcher raises confidence a little,
        # but never turns two weak signals into a certainty.
        existing.score = min(0.97, max(existing.score, g.score) + 0.06)
        existing.evidence.extend(g.evidence)
        if existing.category is Category.UNKNOWN and g.category is not Category.UNKNOWN:
            existing.category = g.category
        if not existing.vendor and g.vendor:
            existing.vendor = g.vendor
        if g.matcher not in existing.matcher:
            existing.matcher = f"{existing.matcher}+{g.matcher}"

    ranked = sorted(merged.values(), key=lambda g: g.score, reverse=True)
    for g in ranked:
        g.confidence = _confidence_for(g.score)

    best = ranked[0] if ranked else None
    # Keep runners-up that are genuinely competitive, not the whole tail.
    runners = [g for g in ranked[1:6] if best and g.score >= best.score * 0.45]

    return Identification(best=best, runners_up=runners, user_label=device.user_label)
