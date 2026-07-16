"""Review battery: verifies every issue called out in the architecture review
and probes weak points the existing tests don't cover.

Sections
--------
1. EVICTED vine memory leak  — vines never pruned from workspace dict
2. Broken L1→L2→L3 pipeline — evicted data not transferred to archive
3. Default pressure_evict_at path — decay skips below 85% (untested)
4. Twilight cycle counting — caller-provided, not tracked internally
5. Compression RAM doubling — anchor held alongside compressed bytes
6. DriftDetector — no reset, edge cases
7. Confidence bands — gates_generation never enforced
8. EnclaveCryptoShield — requires explicit verified provider configuration
9. Lifecycle completeness — reinforce edge cases, empty workspace, etc.
10. Proximity edge cases — zero vectors, negative similarity, age
11. Conflict / fossil edge cases — double-fossilize, resurrect mutation
12. Archive edge cases — empty search, dimension mismatch
13. Oracle integration — end-to-end lifecycle gaps
14. Tidal split — 0, 1, 2 crests
15. Thread safety — concurrent mutation (documented as unsupported)
"""

import math
import time
from inspect import signature

import numpy as np
import pytest

from echo_veil import Oracle, WorkspaceConfig
from echo_veil.archive import ColdArchive, MetadataIndex
from echo_veil.caretaker import gardeners_report
from echo_veil.confidence import ConfidenceBand, classify
from echo_veil.conflict import (
    FOSSIL_MAX_BYTES,
    RESURRECTION_BASELINE,
    FossilizedEcho,
    fossilize,
    in_peer_review_zone,
    open_conflict,
    resurrect,
)
from echo_veil.crypto_shield import CryptoShield, EnclaveCryptoShield, NullCryptoShield
from echo_veil.drift import DriftDetector
from echo_veil.proximity import ProximityConfig, proximity_score
from echo_veil.vectors import as_vector, centroid, cosine_similarity, normalize
from echo_veil.vine import Vine, VineState
from echo_veil.workspace import (
    REINFORCEMENT_BONUS,
    TWILIGHT_THRESHOLD,
    Workspace,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ws(capacity=400, evict_at=0.85):
    """Workspace with realistic defaults (tests can override)."""
    return Workspace(WorkspaceConfig(capacity=capacity, pressure_evict_at=evict_at))


def _forced_ws(capacity=2):
    """Workspace that always runs the decay scan (evict_at=0)."""
    return Workspace(WorkspaceConfig(capacity=capacity, pressure_evict_at=0.0))


def _vec(*components):
    return np.array(components, dtype=np.float64)


# ===========================================================================
# 1. EVICTED vine memory leak — vines never pruned from workspace dict
# ===========================================================================


class TestEvictedVineLeak:
    """FIXED: evicted vines are cleaned up via Workspace.prune_evicted().

    Call prune_evicted() after archiving to remove EVICTED vines from the dict.
    """

    def test_evicted_vine_in_dict_until_pruned(self):
        """After eviction, vine is reachable via get() until prune_evicted()."""
        ws = _forced_ws(capacity=2)
        v = ws.add(Vine("leaker", _vec(0.0, 1.0)))
        ws.run_decay_cycle(_vec(1.0, 0.0))
        assert v.state == VineState.TWILIGHT

        # Advance past twilight window
        now = time.time()
        ws.run_decay_cycle(
            _vec(1.0, 0.0),
            now=now + 31 * 60,
            cycles_since_twilight={v.vine_id: 5},
        )
        assert v.state == VineState.EVICTED

        # Vine is in dict until prune_evicted() is called
        assert ws.get(v.vine_id) is not None

        # After pruning, vine is gone
        ws.prune_evicted()
        assert ws.get(v.vine_id) is None

    def test_prune_evicted_cleans_up_multiple_vines(self):
        """Multiple evictions are cleaned up by prune_evicted()."""
        ws = _forced_ws(capacity=10)
        now = time.time()
        ids = []
        for i in range(5):
            v = ws.add(Vine(f"v{i}", _vec(0.0, 1.0)))
            ids.append(v.vine_id)

        # Demote all to twilight
        ws.run_decay_cycle(_vec(1.0, 0.0), now=now)

        # Evict all
        ws.run_decay_cycle(
            _vec(1.0, 0.0),
            now=now + 31 * 60,
            cycles_since_twilight={vid: 5 for vid in ids},
        )

        # All 5 are EVICTED
        live_count = sum(1 for v in ws.vines if v.state != VineState.EVICTED)
        assert live_count == 0

        # prune_evicted removes them all
        pruned = ws.prune_evicted()
        assert len(pruned) == 5
        assert len(ws._vines) == 0

    def test_pressure_after_prune(self):
        """After prune_evicted(), pressure() and _vines are both clean."""
        ws = _forced_ws(capacity=10)
        now = time.time()
        v = ws.add(Vine("x", _vec(0.0, 1.0)))
        ws.run_decay_cycle(_vec(1.0, 0.0), now=now)
        ws.run_decay_cycle(
            _vec(1.0, 0.0),
            now=now + 31 * 60,
            cycles_since_twilight={v.vine_id: 5},
        )
        assert v.state == VineState.EVICTED
        assert ws.pressure() == 0.0

        # After pruning, dict is empty too
        ws.prune_evicted()
        assert len(ws._vines) == 0

    def test_oracle_archives_evicted_vine_payload(self):
        """Evicted vines get indexed in L2 and their payload reaches L3."""
        oracle = Oracle(WorkspaceConfig(capacity=2, pressure_evict_at=0.0))
        v = oracle.sprout("topic", _vec(0.0, 1.0))
        oracle.observe(_vec(1.0, 0.0))  # demote to twilight

        # Push twilight_since back so the 30-minute clock fires
        v.twilight_since -= 3600

        # Run enough observe cycles to accumulate TWILIGHT_CYCLES internally
        for _ in range(6):
            oracle.observe(_vec(1.0, 0.0))

        # L2 index has the anchor
        results = oracle.index.search(_vec(0.0, 1.0), top_k=1)
        assert len(results) >= 1, "L2 index should contain the evicted vine anchor"

        # L3 archive now receives the evicted vine payload
        assert len(oracle.archive) >= 1, (
            "ColdArchive should contain the evicted vine payload"
        )

    def test_oracle_tracks_twilight_cycles_internally(self):
        """Oracle.observe now tracks twilight cycle counts internally via
        the workspace._twilight_cycles counter.
        """
        oracle = Oracle(WorkspaceConfig(capacity=2, pressure_evict_at=0.0))
        v = oracle.sprout("off", _vec(0.0, 1.0))
        oracle.observe(_vec(1.0, 0.0))  # demote to twilight

        # Run 10 observe cycles without any time passing.
        for _ in range(10):
            oracle.observe(_vec(1.0, 0.0))

        # Vine is still twilight (30 minutes not elapsed)
        assert v.state == VineState.TWILIGHT, (
            "Vine should still be in TWILIGHT because 30 minutes have not elapsed"
        )

        # But the cycle counter should have advanced
        assert oracle.workspace._twilight_cycles.get(v.vine_id, 0) >= 5, (
            "Internal twilight cycle counter should have advanced past 5"
        )

    def test_decay_runs_when_pressure_below_threshold(self):
        """With default config, a mostly-empty workspace still runs decay."""
        ws = _ws(capacity=100, evict_at=0.85)
        v = ws.add(Vine("off-topic", _vec(0.0, 1.0)))

        # pressure is 1/100 = 0.01, well below 0.85
        assert ws.pressure() < 0.85

        report = ws.run_decay_cycle(_vec(1.0, 0.0))

        assert v.score < TWILIGHT_THRESHOLD
        assert v.state == VineState.TWILIGHT
        assert report["demoted"] == [v.vine_id]
        assert report["evicted"] == []

    def test_decay_fires_when_pressure_exceeds_threshold(self):
        """When pressure crosses 85%, the scan should demote low-scoring vines."""
        ws = _ws(capacity=4, evict_at=0.85)
        # Add 4 vines to reach 100% pressure
        for i in range(4):
            ws.add(Vine(f"v{i}", _vec(float(i), 0.0)))

        assert ws.pressure() == 1.0  # 4/4 > 0.85

        # Intent aligned with v[0] only; others should demote
        report = ws.run_decay_cycle(_vec(0.0, 1.0))
        # At least some should be demoted
        assert len(report["demoted"]) > 0

    def test_rescore_still_happens_at_low_pressure(self):
        """Low pressure still updates scores before lifecycle changes."""
        ws = _ws(capacity=100, evict_at=0.85)
        v = ws.add(Vine("off", _vec(0.0, 1.0)))

        assert v.score == 1.0  # initial default
        ws.run_decay_cycle(_vec(1.0, 0.0))

        assert v.score < 1.0, "Score should be rescored at low pressure"
        assert v.state == VineState.TWILIGHT


# ===========================================================================
# 4. Twilight cycle counting — caller-provided, not tracked internally
# ===========================================================================


class TestTwilightCycleCounting:
    """BUG: Workspace does not track how many decay cycles a vine has been in
    TWILIGHT. The caller must supply cycles_since_twilight, which is a
    footgun — if omitted, eviction falls back to the 30-minute clock alone.

    Callers can still override via cycles_since_twilight, but it is no longer required.
    """

    def test_cycles_not_tracked_internally(self):
        """Without passing cycles_since_twilight, a vine in twilight for
        many cycles but less than 30 minutes is never evicted."""
        ws = _forced_ws(capacity=2)
        v = ws.add(Vine("stuck", _vec(0.0, 1.0)))
        now = time.time()

        ws.run_decay_cycle(_vec(1.0, 0.0), now=now)
        assert v.state == VineState.TWILIGHT

        # Run 100 decay cycles without advancing time and without
        # passing cycles_since_twilight
        for _ in range(100):
            ws.run_decay_cycle(_vec(1.0, 0.0), now=now)

        # Vine is still TWILIGHT — cycles are not tracked
        assert v.state == VineState.TWILIGHT, (
            "Vine should still be TWILIGHT because cycle count is not tracked"
        )

    def test_eviction_requires_both_conditions_by_default(self):
        """The spec says "5 cycles OR 30 minutes, whichever is longer."
        The implementation uses AND (both must be true). With the default
        empty cycles dict, the cycle condition defaults to TWILIGHT_CYCLES=5,
        so only the time condition matters.

        PATCH: The spec says "whichever is longer" which means OR, not AND.
        The implementation uses AND. This may be intentional but should be
        documented.
        """
        ws = _forced_ws(capacity=2)
        v = ws.add(Vine("test", _vec(0.0, 1.0)))
        now = time.time()

        ws.run_decay_cycle(_vec(1.0, 0.0), now=now)
        assert v.state == VineState.TWILIGHT

        # 60 minutes have passed (well over 30 min), but only 1 cycle
        later = now + 60 * 60
        ws.run_decay_cycle(
            _vec(1.0, 0.0),
            now=later,
            cycles_since_twilight={v.vine_id: 1},  # only 1 cycle
        )
        # With AND logic: 1 cycle < 5, so NOT evicted even though 60 min > 30
        assert v.state == VineState.TWILIGHT, (
            "AND logic prevents eviction when only time condition is met"
        )


# ===========================================================================
# 5. Compression RAM doubling — anchor held alongside compressed bytes
# ===========================================================================


class TestCompressionRAM:
    """FIXED: Vine.compress() now zeros the anchor array after compression.
    In TWILIGHT state, only the compressed bytes are held, not the full anchor.

    decompress() restores the anchor from the compressed form.
    """

    def test_anchor_released_after_compress(self):
        """After compress(), the anchor array is released (zeroed)."""
        v = Vine("test", np.arange(768, dtype=np.float64))
        v.compress()

        # _compressed is set
        assert v._compressed is not None
        # Anchor is now zeroed after compression
        assert v.anchor.shape == (0,), (
            "Anchor should be zeroed after compression to save RAM"
        )

    def test_compression_ratio_on_realistic_vector(self):
        """Verify that the achieved compression ratio is reported honestly.
        Random-ish data (arange) should compress but not hit 88%."""
        v = Vine("test", np.arange(768, dtype=np.float64))
        ratio = v.compress()
        # arange compresses well but not 88%
        assert 0.0 < ratio < 1.0, f"Compression ratio should be in (0,1), got {ratio}"
        # It should be less than 88% for sequential data
        assert ratio < 0.88, (
            f"Compression ratio {ratio:.2%} exceeds the spec's 88% claim "
            f"for this data — the implementation correctly reports actual ratio"
        )

    def test_decompress_restores_anchor(self):
        """After decompress(), the anchor should be identical to the original."""
        v = Vine("test", np.arange(768, dtype=np.float64))
        original = v.anchor.copy()
        v.compress()
        v.decompress()
        assert np.allclose(v.anchor, original)
        assert v._compressed is None


# ===========================================================================
# 6. DriftDetector — no reset, edge cases
# ===========================================================================


class TestDriftDetectorEdgeCases:
    """FIXED: DriftDetector now has a reset() method that clears observed
    intents and the latched drifting state. Useful for session resets.
    """

    def test_reset_method(self):
        """DriftDetector.reset() clears the latched drifting state and history."""
        d = DriftDetector()
        centroid = _vec(1.0, 0.0)

        # Drive into drifting state
        for _ in range(3):
            d.observe(_vec(0.0, 1.0))
        assert d.is_drifting(centroid) is True

        # reset() clears the latched state
        d.reset()
        assert d._drifting is False, "reset() should clear the drifting flag"
        assert len(d._recent) == 0, "reset() should clear observed intents"

    def test_drift_with_empty_window(self):
        """drift() on an empty detector should return 0.0."""
        d = DriftDetector()
        centroid = _vec(1.0, 0.0)
        assert d.drift(centroid) == 0.0

    def test_is_drifting_with_empty_window(self):
        """is_drifting() on an empty detector should return False."""
        d = DriftDetector()
        assert d.is_drifting(_vec(1.0, 0.0)) is False

    def test_drift_latches_and_unlatches(self):
        """Verify the full hysteresis cycle: not drifting → drifting → not drifting."""
        d = DriftDetector()
        centroid = _vec(1.0, 0.0)

        # Start aligned
        for _ in range(3):
            d.observe(_vec(1.0, 0.0))
        assert d.is_drifting(centroid) is False

        # Drive orthogonal — should latch
        for _ in range(3):
            d.observe(_vec(0.0, 1.0))
        assert d.is_drifting(centroid) is True

        # Return to aligned — should unlatch
        for _ in range(3):
            d.observe(_vec(1.0, 0.0))
        assert d.is_drifting(centroid) is False

    def test_drift_magnitude_range(self):
        """drift() returns 1 - cosine_similarity, which can be negative
        if vectors are very similar (cos > 1 due to float precision)."""
        d = DriftDetector()
        d.observe(_vec(1.0, 0.0))
        # Identical vectors should give drift ≈ 0
        assert d.drift(_vec(1.0, 0.0)) == pytest.approx(0.0, abs=1e-10)


# ===========================================================================
# 7. Confidence bands — gates_generation never enforced
# ===========================================================================


class TestConfidenceGating:
    """FIXED: Oracle.check_generation_gate() now enforces gates_generation.
    INFERENTIAL raises GenerationGated (overridable); OBSCURITY is a hard stop.


    """

    def test_inferential_band_gates_generation(self):
        """INFERENTIAL band has gates_generation=True but nothing enforces it."""
        policy = classify(0.40)
        assert policy.band == ConfidenceBand.INFERENTIAL
        assert policy.gates_generation is True

    def test_obscurity_band_gates_generation(self):
        """OBSCURITY band has gates_generation=True but nothing enforces it."""
        policy = classify(0.10)
        assert policy.band == ConfidenceBand.OBSCURITY
        assert policy.gates_generation is True

    def test_solid_band_does_not_gate(self):
        policy = classify(0.90)
        assert policy.gates_generation is False

    def test_no_enforcement_in_oracle(self):
        """Oracle has no method that checks gates_generation."""
        oracle = Oracle(WorkspaceConfig(capacity=5))
        # Oracle does not expose any confidence-gating method
        assert not hasattr(oracle, "check_confidence"), (
            "Oracle should have a method that checks confidence bands "
            "before allowing generation"
        )


# ===========================================================================
# 8. EnclaveCryptoShield — requires explicit provider configuration
# ===========================================================================


class TestCryptoShieldAPI:
    """EnclaveCryptoShield fails closed when its trust dependencies are absent."""

    def test_enclave_shield_requires_provider_configuration(self):
        with pytest.raises(TypeError, match="missing a required argument"):
            signature(EnclaveCryptoShield).bind()

    def test_null_shield_passes_through(self):
        shield = NullCryptoShield(silence_warning=True)
        anchor = _vec(1.0, 0.0)
        protected = shield.protect(anchor)
        assert np.array_equal(protected, anchor)

        sim = shield.similarity(_vec(1.0, 0.0), protected)
        assert pytest.approx(sim) == 1.0

    def test_null_shield_warns_by_default(self):
        with pytest.warns(UserWarning, match="NO confidentiality"):
            NullCryptoShield()

    def test_oracle_production_refuses_without_shield(self):
        with pytest.raises(RuntimeError, match="production"):
            Oracle(environment="production")

    def test_oracle_production_refuses_explicit_null_shield(self):
        """Production must reject NullCryptoShield even when passed explicitly."""
        with pytest.raises(RuntimeError, match="EnclaveCryptoShield"):
            Oracle(
                environment="production",
                shield=NullCryptoShield(silence_warning=True),
            )

    def test_oracle_production_rejects_unmarked_custom_shield(self):
        """Two callable methods alone must not bypass the production guard."""

        class DummyShield:
            def protect(self, anchor):
                return anchor

            def similarity(self, intent, protected_anchor):
                return 1.0

        with pytest.raises(RuntimeError, match="EnclaveCryptoShield"):
            Oracle(environment="production", shield=DummyShield())

    def test_crypto_shield_protocol(self):
        """CryptoShield is a Protocol — verify the interface."""
        assert hasattr(CryptoShield, "protect")
        assert hasattr(CryptoShield, "similarity")


# ===========================================================================
# 9. Lifecycle completeness — reinforce edge cases, empty workspace, etc.
# ===========================================================================


class TestReinforceEdgeCases:
    """Edge cases around the reinforce (snap-back) operation."""

    def test_reinforce_active_vine_only_touches(self):
        """Reinforcing an ACTIVE vine should only touch it, not add the bonus."""
        ws = _forced_ws(capacity=10)
        v = ws.add(Vine("active", _vec(1.0, 0.0)))
        score_before = v.score
        ws.reinforce(v.vine_id)
        assert v.state == VineState.ACTIVE
        # Score should NOT get the bonus for an already-active vine
        assert v.score == score_before, (
            "Reinforcing an ACTIVE vine should not change its score"
        )

    def test_reinforce_evicted_vine(self):
        """Reinforcing an EVICTED vine fails explicitly and cannot resurrect it."""
        ws = _forced_ws(capacity=2)
        v = ws.add(Vine("gone", _vec(0.0, 1.0)))
        now = time.time()
        ws.run_decay_cycle(_vec(1.0, 0.0), now=now)
        ws.run_decay_cycle(
            _vec(1.0, 0.0),
            now=now + 31 * 60,
            cycles_since_twilight={v.vine_id: 5},
        )
        assert v.state == VineState.EVICTED

        with pytest.raises(ValueError, match="evicted"):
            ws.reinforce(v.vine_id)
        assert v.state == VineState.EVICTED

    def test_reinforce_twilight_vine_gets_bonus(self):
        """Reinforcing a TWILIGHT vine snaps it back with +0.08 bonus."""
        ws = _forced_ws(capacity=2)
        v = ws.add(Vine("twilight", _vec(0.0, 1.0)))
        ws.run_decay_cycle(_vec(1.0, 0.0))
        assert v.state == VineState.TWILIGHT
        score_before = v.score

        ws.reinforce(v.vine_id)
        assert v.state == VineState.ACTIVE
        assert v.score == pytest.approx(score_before + REINFORCEMENT_BONUS)

    def test_reinforce_bonus_capped_at_1(self):
        """Reinforcement bonus should not push score above 1.0."""
        ws = _forced_ws(capacity=2)
        v = ws.add(Vine("high", _vec(0.99, 0.01)))
        v.score = 0.97  # artificially high
        ws.run_decay_cycle(_vec(1.0, 0.0))
        # If score stays above 0.42, vine stays ACTIVE
        # Force twilight by setting state directly
        v.state = VineState.TWILIGHT
        v.twilight_since = time.time()
        v.score = 0.97

        ws.reinforce(v.vine_id)
        assert v.score <= 1.0, f"Score should be capped at 1.0, got {v.score}"


class TestEmptyWorkspace:
    """Edge cases with an empty workspace."""

    def test_decay_cycle_on_empty_workspace(self):
        ws = _forced_ws(capacity=10)
        report = ws.run_decay_cycle(_vec(1.0, 0.0))
        assert report == {"demoted": [], "evicted": []}

    def test_pressure_on_empty_workspace(self):
        ws = Workspace(WorkspaceConfig(capacity=10))
        assert ws.pressure() == 0.0

    def test_pressure_on_zero_capacity(self):
        with pytest.raises(ValueError, match="positive integer"):
            WorkspaceConfig(capacity=0)

    def test_active_on_empty_workspace(self):
        ws = Workspace(WorkspaceConfig(capacity=10))
        assert ws.active() == []

    def test_tidal_split_with_no_crests(self):
        ws = Workspace(WorkspaceConfig(capacity=10))
        result = ws.tidal_split()
        assert result == {}, "No crests should yield empty split"

    def test_gardeners_report_on_empty_workspace(self):
        ws = Workspace(WorkspaceConfig(capacity=10))
        report = gardeners_report(ws)
        assert report.thriving_vines == 0
        assert report.twilight_grove == 0
        assert report.knotted_branches == 0
        assert report.ancient_rings == 0
        assert report.memory_pressure == 0.0


class TestWorkspaceCapacity:
    """Edge cases around capacity boundaries."""

    def test_single_vine_at_capacity_one(self):
        ws = _forced_ws(capacity=1)
        ws.add(Vine("only", _vec(1.0, 0.0)))
        assert ws.pressure() == 1.0

    def test_adding_vines_beyond_capacity(self):
        """Workspace doesn't enforce capacity on add() — it's advisory
        for the decay loop, not a hard cap."""
        ws = _forced_ws(capacity=2)
        for i in range(5):
            ws.add(Vine(f"v{i}", _vec(float(i), 0.0)))
        assert len(ws.vines) == 5
        assert ws.pressure() > 1.0

        report = ws.run_decay_cycle(_vec(1.0, 0.0))

        assert len(report["evicted"]) == 3
        assert ws.pressure() == 1.0


# ===========================================================================
# 10. Proximity edge cases — zero vectors, negative similarity, age
# ===========================================================================


class TestProximityEdgeCases:
    def test_zero_intent_vector(self):
        """Zero intent vector: cosine=0, score is the recency bonus alone (0.15 at Δt=0)."""
        score = proximity_score(_vec(0.0, 0.0), _vec(1.0, 0.0), age_hours=0.0)
        assert math.isclose(score, 0.15, abs_tol=1e-9)

    def test_zero_anchor_vector(self):
        """Zero anchor vector: cosine=0, score is the recency bonus alone (0.15 at Δt=0)."""
        score = proximity_score(_vec(1.0, 0.0), _vec(0.0, 0.0), age_hours=0.0)
        assert math.isclose(score, 0.15, abs_tol=1e-9)

    def test_negative_cosine_reduces_score(self):
        """Opposite vectors: cosine=-1, score = -1 + 0.15 = -0.85 (no clamping per spec)."""
        score = proximity_score(_vec(1.0, 0.0), _vec(-1.0, 0.0), age_hours=0.0)
        assert math.isclose(score, -0.85, abs_tol=1e-9)

    def test_very_stale_vine_recency_bonus_decays(self):
        """After 1000 hours the recency bonus is negligible; cosine dominates."""
        import math as _math

        score = proximity_score(_vec(1.0, 0.0), _vec(1.0, 0.0), age_hours=1000.0)
        # cosine=1 stays 1; recency ≈ 0; total ≈ 1.0
        assert _math.isclose(score, 1.0, abs_tol=0.01)
        # orthogonal vectors: cosine=0, recency≈0 → near zero
        orth_score = proximity_score(_vec(1.0, 0.0), _vec(0.0, 1.0), age_hours=1000.0)
        assert orth_score < 0.001

    def test_negative_age_clamped(self):
        """Negative age (future timestamp) should be clamped to 0."""
        # This tests the max(0.0, ...) in Vine.age_hours
        v = Vine("test", _vec(1.0, 0.0))
        v.last_touched = time.time() + 10000  # future
        age = v.age_hours()
        assert age == 0.0, f"Negative age should be clamped to 0, got {age}"

    def test_custom_time_constant(self):
        """A shorter time constant decays the recency bonus faster."""
        cfg_short = ProximityConfig(time_constant_hours=1.0)
        cfg_long = ProximityConfig(time_constant_hours=24.0)
        score_short = proximity_score(_vec(1.0, 0.0), _vec(1.0, 0.0), 6.0, cfg_short)
        score_long = proximity_score(_vec(1.0, 0.0), _vec(1.0, 0.0), 6.0, cfg_long)
        assert score_short < score_long


# ===========================================================================
# 11. Conflict / fossil edge cases
# ===========================================================================


class TestConflictEdgeCases:
    def test_fossilize_already_resolved_conflict(self):
        """A resolved conflict cannot produce duplicate fossil artifacts."""
        c = open_conflict("topic", "a", "b", 0.8, 0.7)
        fossilize(c, summary="first")
        assert c.resolved is True

        with pytest.raises(ValueError, match="already resolved"):
            fossilize(c, summary="second")

    def test_resurrect_mutates_original_fossil(self):
        """resurrect() mutates the FossilizedEcho's timeline in place.
        This is by design (evolving timeline) but worth documenting."""
        c = open_conflict("topic", "a", "b", 0.8, 0.7)
        echo = fossilize(c, summary="settled")
        initial_timeline_len = len(echo.timeline)

        resurrect(echo)
        assert len(echo.timeline) == initial_timeline_len + 1
        assert any(e["event"] == "resurrected" for e in echo.timeline)

    def test_conflict_with_equal_strengths(self):
        """Equal strengths should be in the peer-review zone (delta=0)."""
        assert in_peer_review_zone(0.5, 0.5) is True
        c = open_conflict("t", "a", "b", 0.5, 0.5)
        assert c.delta == 0.0

    def test_conflict_at_exact_peer_review_boundary(self):
        """Delta exactly 0.15 should be in the zone (<=)."""
        # Use values whose difference is exactly 0.15 in IEEE 754 (avoid 0.90-0.75=0.15000...002)
        assert in_peer_review_zone(1.00, 0.85) is True
        assert in_peer_review_zone(1.00, 0.84) is False  # 0.16 > 0.15

    def test_fossil_serialize_exact_max_size(self):
        """A fossil at exactly the 2KB limit should serialize without error."""
        c = open_conflict("t", "a", "b", 0.5, 0.5)
        # Create a summary that fills close to 2KB
        # The JSON overhead is small, so we can use most of 2048 bytes
        summary = "x" * 1900  # Leave room for JSON structure
        echo = fossilize(c, summary=summary)
        payload = echo.serialize()
        assert len(payload) <= FOSSIL_MAX_BYTES

    def test_resurrect_baseline_is_neutral(self):
        """Resurrected conflict should start both sides at 0.55."""
        c = open_conflict("t", "a", "b", 0.99, 0.10)
        echo = fossilize(c, summary="done")
        revived = resurrect(echo)
        assert revived.strength_a == RESURRECTION_BASELINE
        assert revived.strength_b == RESURRECTION_BASELINE
        assert revived.resolved is False


# ===========================================================================
# 12. Archive edge cases
# ===========================================================================


class TestArchiveEdgeCases:
    def test_metadata_index_search_empty(self):
        idx = MetadataIndex()
        results = idx.search(_vec(1.0, 0.0), top_k=5)
        assert results == []

    def test_metadata_index_search_top_k_larger_than_entries(self):
        idx = MetadataIndex()
        idx.upsert("a", _vec(1.0, 0.0))
        results = idx.search(_vec(1.0, 0.0), top_k=10)
        assert len(results) == 1

    def test_metadata_index_upsert_replaces(self):
        idx = MetadataIndex()
        idx.upsert("a", _vec(1.0, 0.0))
        idx.upsert("a", _vec(0.0, 1.0))  # replace
        assert len(idx) == 1
        results = idx.search(_vec(0.0, 1.0), top_k=1)
        assert results[0][0] == "a"

    def test_cold_archive_put_get(self):
        arc = ColdArchive()
        arc.put("key1", b"data1")
        assert arc.get("key1") == b"data1"
        assert arc.get("missing") is None

    def test_cold_archive_overwrite(self):
        arc = ColdArchive()
        arc.put("key1", b"original")
        arc.put("key1", b"updated")
        assert arc.get("key1") == b"updated"


# ===========================================================================
# 13. Oracle integration — end-to-end lifecycle gaps
# ===========================================================================


class TestOracleIntegration:
    def test_oracle_observe_demotes_and_reports(self):
        oracle = Oracle(WorkspaceConfig(capacity=2, pressure_evict_at=0.0))
        oracle.sprout("keep", _vec(1.0, 0.0))
        drop = oracle.sprout("drop", _vec(0.0, 1.0))
        report = oracle.observe(_vec(1.0, 0.0))
        assert "demoted" in report
        assert drop.vine_id in report["demoted"]

    def test_oracle_report_counts(self):
        oracle = Oracle(WorkspaceConfig(capacity=5, pressure_evict_at=0.0))
        oracle.sprout("a", _vec(1.0, 0.0))
        oracle.sprout("b", _vec(0.0, 1.0))
        oracle.observe(_vec(1.0, 0.0))
        r = oracle.report()
        assert r.thriving_vines == 1
        assert r.twilight_grove == 1

    def test_oracle_garden_centroid(self):
        oracle = Oracle(WorkspaceConfig(capacity=5))
        oracle.sprout("a", _vec(1.0, 0.0))
        oracle.sprout("b", _vec(0.0, 1.0))
        c = oracle.garden_centroid()
        assert c is not None
        expected = _vec(0.5, 0.5)
        assert np.allclose(c, expected)

    def test_oracle_garden_centroid_empty(self):
        oracle = Oracle(WorkspaceConfig(capacity=5))
        assert oracle.garden_centroid() is None

    def test_oracle_is_drifting_empty_workspace(self):
        oracle = Oracle(WorkspaceConfig(capacity=5))
        assert oracle.is_drifting() is False

    def test_oracle_reinforce(self):
        oracle = Oracle(WorkspaceConfig(capacity=2, pressure_evict_at=0.0))
        v = oracle.sprout("off", _vec(0.0, 1.0))
        oracle.observe(_vec(1.0, 0.0))
        assert v.state == VineState.TWILIGHT
        oracle.reinforce(v.vine_id)
        assert v.state == VineState.ACTIVE

    def test_oracle_no_l3_archive_on_eviction(self):
        """Verify that evicted vines don't reach the ColdArchive."""
        oracle = Oracle(WorkspaceConfig(capacity=2, pressure_evict_at=0.0))
        v = oracle.sprout("off", _vec(0.0, 1.0))
        oracle.observe(_vec(1.0, 0.0))  # demote

        # Manually evict
        now = time.time()
        oracle.workspace.run_decay_cycle(
            _vec(1.0, 0.0),
            now=now + 31 * 60,
            cycles_since_twilight={v.vine_id: 5},
        )
        assert v.state == VineState.EVICTED
        # L3 archive should still be empty
        assert len(oracle.archive) == 0


# ===========================================================================
# 14. Tidal split — 0, 1, 2 crests
# ===========================================================================


class TestTidalSplitEdgeCases:
    def test_tidal_split_with_one_crest(self):
        ws = Workspace(WorkspaceConfig(capacity=10))
        v = ws.add(Vine("only", _vec(1.0, 0.0)))
        ws.set_crests([v.vine_id])
        split = ws.tidal_split()
        assert "primary" in split
        assert "secondary" not in split
        assert split["primary"] == pytest.approx(0.70)

    def test_tidal_split_with_two_crests(self):
        ws = Workspace(WorkspaceConfig(capacity=10))
        v1 = ws.add(Vine("a", _vec(1.0, 0.0)))
        v2 = ws.add(Vine("b", _vec(0.0, 1.0)))
        ws.set_crests([v1.vine_id, v2.vine_id])
        split = ws.tidal_split()
        assert "primary" in split
        assert "secondary" in split
        assert "tertiary" not in split
        assert split["primary"] == pytest.approx(0.70)
        assert split["secondary"] == pytest.approx(0.18)

    def test_tidal_split_with_no_crests(self):
        ws = Workspace(WorkspaceConfig(capacity=10))
        split = ws.tidal_split()
        assert split == {}

    def test_set_crests_with_unknown_vine(self):
        ws = Workspace(WorkspaceConfig(capacity=10))
        with pytest.raises(KeyError):
            ws.set_crests(["nonexistent"])


# ===========================================================================
# 15. Thread safety — concurrent mutation (documented as unsupported)
# ===========================================================================


class TestThreadSafety:
    """Workspace concurrency is documented as degraded, not silently safe."""

    def test_capability_report_documents_thread_safety_risk(self):
        oracle = Oracle(WorkspaceConfig(capacity=100, pressure_evict_at=0.0))
        report = oracle.capability_report().as_dict()
        assert report["thread_safety"]["status"] == "degraded"
        assert "reentrant locks" in report["thread_safety"]["message"]
        assert "mutable" in report["thread_safety"]["known_limitations"][0]


# ===========================================================================
# 16. Vector utility edge cases
# ===========================================================================


class TestVectorEdgeCases:
    def test_normalize_zero_vector(self):
        result = normalize(_vec(0.0, 0.0))
        assert np.allclose(result, _vec(0.0, 0.0))

    def test_cosine_similarity_dimension_mismatch(self):
        with pytest.raises(ValueError, match="dimension mismatch"):
            cosine_similarity(_vec(1.0, 0.0), _vec(1.0, 0.0, 0.0))

    def test_cosine_similarity_identical_vectors(self):
        v = _vec(3.0, 4.0)
        assert cosine_similarity(v, v) == pytest.approx(1.0)

    def test_cosine_similarity_opposite_vectors(self):
        assert cosine_similarity(_vec(1.0, 0.0), _vec(-1.0, 0.0)) == pytest.approx(-1.0)

    def test_centroid_single_vector(self):
        v = _vec(1.0, 2.0, 3.0)
        assert np.allclose(centroid([v]), v)

    def test_centroid_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            centroid([])

    def test_as_vector_2d_raises(self):
        with pytest.raises(ValueError, match="1-D"):
            as_vector(np.array([[1.0, 0.0]]))


# ===========================================================================
# 17. Vine lifecycle state machine
# ===========================================================================


class TestVineStateMachine:
    """Verify the legal state transitions and catch illegal ones."""

    def test_active_to_twilight(self):
        ws = _forced_ws(capacity=2)
        v = ws.add(Vine("v", _vec(0.0, 1.0)))
        ws.run_decay_cycle(_vec(1.0, 0.0))
        assert v.state == VineState.TWILIGHT

    def test_twilight_to_evicted(self):
        ws = _forced_ws(capacity=2)
        v = ws.add(Vine("v", _vec(0.0, 1.0)))
        now = time.time()
        ws.run_decay_cycle(_vec(1.0, 0.0), now=now)
        ws.run_decay_cycle(
            _vec(1.0, 0.0),
            now=now + 31 * 60,
            cycles_since_twilight={v.vine_id: 5},
        )
        assert v.state == VineState.EVICTED

    def test_twilight_to_active_via_reinforce(self):
        ws = _forced_ws(capacity=2)
        v = ws.add(Vine("v", _vec(0.0, 1.0)))
        ws.run_decay_cycle(_vec(1.0, 0.0))
        assert v.state == VineState.TWILIGHT
        ws.reinforce(v.vine_id)
        assert v.state == VineState.ACTIVE

    def test_evicted_is_terminal(self):
        """Once EVICTED, a vine cannot transition back through reinforce()."""
        ws = _forced_ws(capacity=2)
        v = ws.add(Vine("v", _vec(0.0, 1.0)))
        now = time.time()
        ws.run_decay_cycle(_vec(1.0, 0.0), now=now)
        ws.run_decay_cycle(
            _vec(1.0, 0.0),
            now=now + 31 * 60,
            cycles_since_twilight={v.vine_id: 5},
        )
        assert v.state == VineState.EVICTED

        with pytest.raises(ValueError, match="evicted"):
            ws.reinforce(v.vine_id)
        assert v.state == VineState.EVICTED

    def test_locked_vine_survives_decay(self):
        ws = _forced_ws(capacity=2)
        v = ws.add(Vine("locked", _vec(0.0, 1.0)))
        ws.lock(v.vine_id)
        ws.run_decay_cycle(_vec(1.0, 0.0))
        assert v.state == VineState.ACTIVE
        assert v.locked is True

    def test_unlock_allows_decay(self):
        ws = _forced_ws(capacity=2)
        v = ws.add(Vine("was-locked", _vec(0.0, 1.0)))
        ws.lock(v.vine_id)
        ws.run_decay_cycle(_vec(1.0, 0.0))
        assert v.state == VineState.ACTIVE

        ws.unlock(v.vine_id)
        ws.run_decay_cycle(_vec(1.0, 0.0))
        assert v.state == VineState.TWILIGHT


# ===========================================================================
# 18. Gardener's Report completeness
# ===========================================================================


class TestGardenersReport:
    def test_report_dict_keys(self):
        ws = Workspace(WorkspaceConfig(capacity=10))
        r = gardeners_report(ws)
        d = r.as_dict()
        assert set(d.keys()) == {
            "thriving_vines",
            "twilight_grove",
            "knotted_branches",
            "ancient_rings",
            "memory_pressure",
        }

    def test_report_with_conflicts_and_fossils(self):
        ws = Workspace(WorkspaceConfig(capacity=10))
        c = open_conflict("t", "a", "b", 0.8, 0.7)
        f = FossilizedEcho(topic="old", summary="settled")
        r = gardeners_report(ws, conflicts=[c], fossils=[f])
        assert r.knotted_branches == 1
        assert r.ancient_rings == 1

    def test_report_resolved_conflict_not_counted(self):
        ws = Workspace(WorkspaceConfig(capacity=10))
        c = open_conflict("t", "a", "b", 0.8, 0.7)
        c.resolved = True
        r = gardeners_report(ws, conflicts=[c])
        assert r.knotted_branches == 0


# ===========================================================================
# 19. Decay loop: multiple cycles and score progression
# ===========================================================================


class TestDecayLoopProgression:
    def test_scores_decrease_with_time(self):
        """Vines that are not touched should have decreasing scores over time."""
        ws = _forced_ws(capacity=10)
        v = ws.add(Vine("stale", _vec(1.0, 0.0)))
        now = time.time()

        scores = []
        for hours in [0, 1, 6, 24]:
            ws.run_decay_cycle(_vec(1.0, 0.0), now=now + hours * 3600)
            scores.append(v.score)

        # Scores should decrease (or stay same) as time passes
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1], (
                f"Score should decrease over time: {scores}"
            )

    def test_touch_resets_decay(self):
        """Touching a vine should reset its age clock."""
        ws = _forced_ws(capacity=10)
        v = ws.add(Vine("fresh", _vec(1.0, 0.0)))
        now = time.time()

        # Let it age 10 hours
        ws.run_decay_cycle(_vec(1.0, 0.0), now=now + 10 * 3600)
        stale_score = v.score

        # Touch it and score again immediately
        v.touch(now + 10 * 3600)
        ws.run_decay_cycle(_vec(1.0, 0.0), now=now + 10 * 3600)
        fresh_score = v.score

        assert fresh_score > stale_score, (
            f"Touching should improve score: stale={stale_score}, fresh={fresh_score}"
        )

    def test_multiple_demotions_in_one_cycle(self):
        """Multiple off-topic vines should be demoted in a single cycle."""
        ws = _forced_ws(capacity=10)
        ids = []
        for i in range(5):
            v = ws.add(Vine(f"off{i}", _vec(0.0, 1.0)))
            ids.append(v.vine_id)

        report = ws.run_decay_cycle(_vec(1.0, 0.0))
        assert len(report["demoted"]) == 5
