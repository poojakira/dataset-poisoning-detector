"""
End-to-end integration tests for the poisoning detection pipeline.

Tests the full path from input sanitization through detection, quarantine
storage, and audit logging, verifying that clean samples pass through
and poisoned samples are properly flagged, quarantined, and audited.
"""

from __future__ import annotations

import os

import numpy as np
import pytest

from poison_detector.audit import AuditConfig, AuditDecision, AuditLogger
from poison_detector.input_sanitizer import InputSanitizer
from poison_detector.storage import SQLiteStore
from poison_detector.stream import StreamingDetector


class TestCleanSamplePassesThroughPipeline:
    """Verify that a clean sample flows through the full pipeline without
    being quarantined, and that an audit log entry is created."""

    def test_clean_sample_passes_through_pipeline(self, tmp_path: object) -> None:
        """A clean sample passes sanitization, scores low, is not quarantined,
        and an audit entry records the approved decision."""
        tmp = tmp_path  # type: ignore[assignment]

        # Set up pipeline components
        sanitizer = InputSanitizer(
            max_dimensions=100,
            min_dimensions=5,
            value_lower_bound=-1000.0,
            value_upper_bound=1000.0,
            enable_rate_limiting=False,
        )
        detector = StreamingDetector(
            window_size=500,
            contamination=0.05,
            zscore_threshold=3.0,
            vote_threshold=2,
        )
        store = SQLiteStore(":memory:")
        audit_logger = AuditLogger(
            AuditConfig(log_path=str(tmp / "audit.jsonl"))
        )

        # Establish baseline with clean data
        rng = np.random.default_rng(42)
        clean_baseline = rng.normal(loc=0.0, scale=1.0, size=(200, 10))
        detector.update_baseline(clean_baseline)

        # Feed a clean sample through the pipeline
        clean_sample = rng.normal(loc=0.0, scale=1.0, size=10).tolist()

        # Step 1: Sanitize
        san_result = sanitizer.sanitize(features=clean_sample, client_id="test-client")
        assert san_result.is_valid, f"Clean sample should pass sanitization: {san_result.rejection_detail}"

        # Step 2: Detect
        score_result = detector.score_sample(san_result.sanitized_sample)
        assert not score_result.is_poisoned, "Clean sample should not be flagged as poisoned"

        # Step 3: Since not poisoned, do NOT quarantine
        # (only quarantine if flagged)
        stats = store.get_stats()
        assert stats.total_entries == 0, "No samples should be quarantined"

        # Step 4: Log audit entry for approved sample
        # Convert numpy bools to native Python bools for JSON serialization
        method_votes_native = {k: bool(v) for k, v in score_result.method_votes.items()}
        entry = audit_logger.append(
            event_type="detection",
            user_id="pipeline:integration-test",
            sample_id="sample-clean-001",
            sample_hash="sha256:test",
            score=score_result.score,
            decision=AuditDecision.APPROVED,
            metadata={"method_votes": method_votes_native},
        )

        # Verify audit entry exists and is correct
        assert entry.decision == "approved"
        assert entry.score == score_result.score
        assert entry.event_type == "detection"
        assert audit_logger.entry_count == 1

        # Verify integrity of the audit chain
        is_valid, broken_at = audit_logger.verify_integrity()
        assert is_valid, f"Audit chain should be valid, broken at index {broken_at}"


class TestPoisonedSampleQuarantinedAndAudited:
    """Verify that an extreme outlier sample is detected, quarantined,
    and properly audited."""

    def test_poisoned_sample_quarantined_and_audited(self, tmp_path: object) -> None:
        """An extreme outlier is flagged by the detector, stored in quarantine,
        and an audit entry records the correct decision."""
        tmp = tmp_path  # type: ignore[assignment]

        # Set up pipeline components
        sanitizer = InputSanitizer(
            max_dimensions=100,
            min_dimensions=5,
            value_lower_bound=-1e6,
            value_upper_bound=1e6,
            enable_rate_limiting=False,
        )
        detector = StreamingDetector(
            window_size=500,
            contamination=0.05,
            zscore_threshold=3.0,
            vote_threshold=1,  # Lower threshold so zscore alone can flag
        )
        store = SQLiteStore(":memory:")
        audit_logger = AuditLogger(
            AuditConfig(log_path=str(tmp / "audit.jsonl"))
        )

        # Establish baseline with tight, clean data (mean=0, std=1)
        rng = np.random.default_rng(42)
        clean_baseline = rng.normal(loc=0.0, scale=1.0, size=(200, 10))
        detector.update_baseline(clean_baseline)

        # Create an extreme outlier (50 standard deviations away)
        poisoned_sample = [50.0] * 10

        # Step 1: Sanitize (should pass - values are within bounds)
        san_result = sanitizer.sanitize(features=poisoned_sample, client_id="test-client")
        assert san_result.is_valid, f"Outlier should pass sanitization: {san_result.rejection_detail}"

        # Step 2: Detect - should be flagged
        score_result = detector.score_sample(san_result.sanitized_sample)
        assert score_result.is_poisoned, (
            f"Extreme outlier should be flagged. Score: {score_result.score}, "
            f"Votes: {score_result.method_votes}"
        )

        # Step 3: Quarantine the flagged sample
        sample_id = store.store_sample(
            sample_data=poisoned_sample,
            scores={"combined": score_result.score, **{k: float(v) for k, v in score_result.method_votes.items()}},
            source="integration-test-pipeline",
            metadata={"is_poisoned": True},
        )

        # Verify quarantine entry
        quarantined = store.get_sample(sample_id)
        assert quarantined is not None, "Sample should be in quarantine"
        assert quarantined.sample_data == poisoned_sample
        assert quarantined.source == "integration-test-pipeline"

        stats = store.get_stats()
        assert stats.total_entries == 1
        assert stats.pending_reviews == 1

        # Step 4: Log audit entry for quarantined sample
        entry = audit_logger.append(
            event_type="detection",
            user_id="pipeline:integration-test",
            sample_id=sample_id,
            sample_hash="sha256:poisoned-test",
            score=score_result.score,
            decision=AuditDecision.QUARANTINED,
            metadata={
                "method_votes": {k: str(v) for k, v in score_result.method_votes.items()},
                "source": "integration-test-pipeline",
            },
        )

        # Verify audit entry
        assert entry.decision == "quarantined"
        assert entry.score == score_result.score
        assert entry.sample_id == sample_id
        assert audit_logger.entry_count == 1

        # Verify we can query by decision
        quarantined_entries = audit_logger.query_by_decision(AuditDecision.QUARANTINED)
        assert len(quarantined_entries) == 1
        assert quarantined_entries[0].sample_id == sample_id

        # Verify integrity of the audit chain
        is_valid, broken_at = audit_logger.verify_integrity()
        assert is_valid, f"Audit chain should be valid, broken at index {broken_at}"
