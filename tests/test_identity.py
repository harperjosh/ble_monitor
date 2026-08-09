"""Identification, continuity and tracker-awareness tests."""

from __future__ import annotations

import time

from blemon import fixtures as fx
from blemon.decode import parse
from blemon.device import Device
from blemon.identity import apply_links, evaluate_all, find_links, identify
from blemon.identity.continuity import MIN_SPECIFICITY, fingerprint, propose_link
from blemon.identity.trackers import AlertLevel
from blemon.models import Advertisement, Category, Confidence, classify_address
from blemon.translate import describe_device, describe_room, one_liner


def make_device(
    raw_frames: list[bytes],
    address: str = "AA:BB:CC:DD:EE:FF",
    random: bool = False,
    rssi: int = -55,
    start: float = 1000.0,
    interval: float = 1.0,
) -> Device:
    device = Device(
        key=address,
        address=address,
        address_type=classify_address(address, random),
        first_seen=start,
        last_seen=start,
    )
    for i, raw in enumerate(raw_frames):
        device.observe(
            parse(
                Advertisement(
                    address=address,
                    timestamp=start + i * interval,
                    rssi=rssi,
                    address_type=classify_address(address, random),
                    raw=raw,
                )
            )
        )
    return device


class TestIdentification:
    def test_airpods_identified_from_the_model_table(self):
        d = make_device([fx.payload(fx.flags(0x1A), fx.airpods(model=0x1420))] * 5)
        ident = identify(d)
        assert ident.best and "AirPods Pro (2nd generation)" in ident.best.label
        assert ident.best.confidence in (Confidence.HIGH, Confidence.CERTAIN)
        assert ident.best.category is Category.AUDIO

    def test_every_guess_carries_its_evidence(self):
        d = make_device([fx.heart_rate()] * 4)
        ident = identify(d)
        assert ident.best and ident.best.evidence
        for guess in [ident.best, *ident.runners_up]:
            assert guess.evidence, f"{guess.label} has no evidence"
            for e in guess.evidence:
                assert e.observation.strip()

    def test_a_company_id_alone_is_only_a_low_confidence_guess(self):
        """Knowing who made the radio is not knowing what the product is."""
        d = make_device([fx.payload(fx.flags(), fx.manufacturer(0x0087, b"\x01\x02"))] * 4)
        ident = identify(d)
        assert ident.best and ident.best.confidence is Confidence.LOW

    def test_corroboration_raises_confidence_but_never_to_certainty(self):
        d = make_device([fx.heart_rate()] * 5)  # name + service UUID + decoded protocol
        ident = identify(d)
        assert ident.best and ident.best.score <= 0.97

    def test_runners_up_are_kept(self):
        d = make_device([fx.keyboard()] * 4)
        ident = identify(d)
        assert ident.best and ident.runners_up

    def test_unidentifiable_device_says_so(self):
        d = make_device([fx.payload(fx.flags())] * 4)
        ident = identify(d)
        assert ident.display_label == "Unidentified device" or (
            ident.best and ident.best.confidence is Confidence.LOW
        )

    def test_a_user_label_wins_and_is_marked_as_not_a_guess(self):
        d = make_device([fx.payload(fx.flags(0x1A), fx.airpods())] * 4)
        d.user_label = "Sam's earbuds"
        ident = identify(d)
        assert ident.display_label == "Sam's earbuds"
        assert ident.to_dict()["is_guess"] is False

    def test_tracker_tag_propagates(self):
        d = make_device([fx.payload(fx.flags(), fx.find_my(separated=True))] * 4)
        assert d.is_tracker


class TestExposure:
    def test_a_public_address_with_a_name_scores_high(self):
        d = make_device([fx.heart_rate()] * 5)
        exposure = d.exposure()
        assert exposure.score >= 70 and exposure.band == "wide open"
        assert any("permanent address" in r for r in exposure.reasons)

    def test_a_rotating_privacy_preserving_device_scores_low(self):
        d = make_device([fx.exposure_notification()] * 5,
                        address="5E:11:A3:7C:90:22", random=True)
        exposure = d.exposure()
        assert exposure.score <= 20
        assert exposure.protections

    def test_score_is_clamped(self):
        for d in (make_device([fx.heart_rate()] * 5),
                  make_device([fx.exposure_notification()] * 5, address="5E:11:A3:7C:90:22", random=True)):
            assert 0 <= d.exposure().score <= 100


class TestContinuity:
    def _rotating(self, address: str, start: float, count: int = 20) -> Device:
        return make_device(
            [fx.payload(fx.flags(0x1A), fx.airpods(), fx.complete_name("Distinctive"))] * count,
            address=address,
            random=True,
            start=start,
            interval=0.5,
        )

    def test_a_distinctive_device_is_linked_across_a_rotation(self):
        old = self._rotating("5E:11:A3:7C:90:22", 1000.0)
        new = self._rotating("6A:9C:04:1F:B7:3D", old.last_seen + 8)
        link = propose_link(old, new)
        assert link is not None
        assert 0.3 <= link.confidence <= 0.85  # never certainty
        assert link.evidence

    def test_a_generic_device_is_refused_rather_than_guessed(self):
        """Two identical iPhones must not be merged into one."""
        old = make_device([fx.payload(fx.flags(0x1A))] * 10,
                          address="5E:11:A3:7C:90:22", random=True, start=1000.0)
        new = make_device([fx.payload(fx.flags(0x1A))] * 10,
                          address="6A:9C:04:1F:B7:3D", random=True, start=1020.0)
        assert fingerprint(old).specificity < MIN_SPECIFICITY
        assert propose_link(old, new) is None

    def test_a_fixed_address_device_is_never_linked(self):
        old = make_device([fx.heart_rate()] * 10, start=1000.0)
        new = make_device([fx.heart_rate()] * 10, address="BB:CC:DD:EE:FF:00", start=1020.0)
        assert propose_link(old, new) is None

    def test_too_long_a_gap_breaks_the_link(self):
        old = self._rotating("5E:11:A3:7C:90:22", 1000.0)
        new = self._rotating("6A:9C:04:1F:B7:3D", old.last_seen + 10_000)
        assert propose_link(old, new) is None

    def test_a_big_signal_jump_breaks_the_link(self):
        old = self._rotating("5E:11:A3:7C:90:22", 1000.0)
        new = self._rotating("6A:9C:04:1F:B7:3D", old.last_seen + 8)
        for _ in range(20):
            new.rssi_history.append((new.last_seen, -100))
        assert propose_link(old, new) is None

    def test_chains_collapse_transitively_and_the_eldest_key_survives(self):
        a = self._rotating("5E:11:A3:7C:90:22", 1000.0)
        b = self._rotating("6A:9C:04:1F:B7:3D", a.last_seen + 6)
        c = self._rotating("7C:2E:DD:31:90:41", b.last_seen + 6)
        devices = {d.key: d for d in (a, b, c)}
        links = find_links(list(devices.values()))
        apply_links(devices, links)
        assert len(devices) == 1
        survivor = next(iter(devices.values()))
        assert survivor.key == a.key  # the oldest record keeps the key
        assert len(survivor.addresses_seen) == 3
        assert survivor.continuity_confidence < 1.0


class TestTrackerAlerts:
    def _tracker(self, duration: float, rssi: int = -60) -> Device:
        d = make_device(
            [fx.payload(fx.flags(), fx.find_my(separated=False))] * 30,
            address="72:0B:5D:E1:44:8C",
            random=True,
            rssi=rssi,
            start=time.time() - duration,
            interval=duration / 30,
        )
        d.identification = identify(d)
        return d

    def test_a_brief_tracker_sighting_is_not_an_alert(self):
        assert evaluate_all([self._tracker(60)]) == []

    def test_a_persistent_tracker_raises_a_notable_alert_with_evidence(self):
        alerts = evaluate_all([self._tracker(20 * 60)])
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.level is AlertLevel.NOTABLE
        assert alert.evidence and alert.false_positive_note

    def test_seeing_it_across_sessions_escalates(self):
        device = self._tracker(20 * 60)
        alerts = evaluate_all([device], session_counts={device.key: 4})
        assert alerts[0].level is AlertLevel.ATTENTION
        assert "4 separate capture sessions" in alerts[0].explanation

    def test_marking_a_device_as_mine_silences_it(self):
        device = self._tracker(60 * 60)
        device.is_mine = True
        assert evaluate_all([device]) == []

    def _separated(self, seconds: float):
        d = make_device(
            [fx.google_find_my_device(unwanted=True)] * 10,
            address="72:0B:5D:E1:44:8C", random=True, rssi=-55,
            start=time.time() - seconds, interval=seconds / 10,
        )
        d.identification = identify(d)
        return d

    def test_a_separated_tracker_that_persists_is_attention(self):
        alerts = evaluate_all([self._separated(20 * 60)])
        assert alerts and alerts[0].level is AlertLevel.ATTENTION

    def test_a_separated_tracker_seen_once_in_passing_is_not_alerted_on(self):
        # Any Apple device in offline-finding mode broadcasts this frame — a
        # powered-off phone in a bag, an AirPods case away from its owner.
        # Firing on first sight fills the panel with warnings about devices
        # whose owners are sitting next to them, which is what teaches people
        # to ignore the alert that matters.
        assert evaluate_all([self._separated(30)]) == []

    def test_a_distant_tracker_is_not_alerted_on(self):
        assert evaluate_all([self._tracker(60 * 60, rssi=-99)]) == []


class TestTranslation:
    def test_device_paragraph_mentions_confidence_not_certainty(self):
        d = make_device([fx.payload(fx.flags(0x1A), fx.airpods())] * 6)
        d.identification = identify(d)
        text = describe_device(d)
        assert text.startswith(("Identified as", "Almost certainly", "Looks like", "Might be"))
        assert "AirPods" in text

    def test_no_mangled_articles_in_front_of_product_names(self):
        d = make_device([fx.payload(fx.flags(0x1A), fx.airpods())] * 6)
        d.identification = identify(d)
        text = describe_device(d)
        assert "an airPods" not in text and "a airPods" not in text

    def test_macos_opacity_is_explained_rather_than_glossed_over(self):
        from blemon.models import AddressType

        d = make_device([fx.payload(fx.flags(0x1A), fx.airpods())] * 4)
        d.address_type = AddressType.OPAQUE
        assert "macOS" in describe_device(d)

    def test_one_liner_marks_a_low_confidence_guess(self):
        d = make_device([fx.payload(fx.flags(), fx.manufacturer(0x0087, b"\x01"))] * 5)
        d.identification = identify(d)
        assert "best guess" in one_liner(d)

    def test_room_summary_counts_rotating_versus_fixed(self):
        devices = [
            make_device([fx.heart_rate()] * 4),
            make_device([fx.payload(fx.flags(0x1A), fx.airpods())] * 4,
                        address="5E:11:A3:7C:90:22", random=True),
        ]
        text = describe_room(devices)
        assert "2 devices in range" in text
        assert "1 of them rotate" in text

    def test_empty_room_points_at_the_diagnostic_command(self):
        assert "blemon doctor" in describe_room([])


class TestPlacement:
    def test_the_radar_angle_is_stable_across_rebuilds(self):
        a = make_device([fx.heart_rate()] * 4)
        b = make_device([fx.heart_rate()] * 4)
        assert a.radar_angle == b.radar_angle

    def test_different_devices_get_different_angles(self):
        a = make_device([fx.heart_rate()] * 4)
        b = make_device([fx.keyboard()] * 4)
        assert a.radar_angle != b.radar_angle

    def test_the_lot_survives_an_address_rotation(self):
        """The city has to stay a learnable place, so the hash must not follow
        the address when we know something more stable about the device."""
        a = make_device([fx.payload(fx.flags(), fx.complete_name("Stable Name"))] * 4,
                        address="5E:11:A3:7C:90:22", random=True)
        b = make_device([fx.payload(fx.flags(), fx.complete_name("Stable Name"))] * 4,
                        address="6A:9C:04:1F:B7:3D", random=True)
        assert a.stable_hash() == b.stable_hash()
