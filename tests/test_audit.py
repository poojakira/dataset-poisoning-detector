"""Tests for the immutable audit trail with tamper detection.

Verifies hash chain integrity, time-range queries, and tamper detection
using real file I/O operations.
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone

from poison_detector.audit import (
    AuditConfig,
    AuditDecision,
    AuditLogger,
)


def test_immutable_append_creates_chain(tmp_path):
    """Each appended entry links to the previous entry via previous_hash."""
    log_path = str(tmp_path / "audit.jsonl")
    config = AuditConfig(log_path=log_path)
    logger = AuditLogger(config=config)

    # Append multiple entries
    entries = []
    for i in range(5):
        entry = logger.append(
            event_type="detection",
            user_id=f"user-{i}",
            sample_id=f"sample-{i}",
            score=0.5 + i * 0.1,
            decision=AuditDecision.FLAGGED,
        )
        entries.append(entry)

    # Verify chain linkage
    genesis_hash = "0" * 64
    assert entries[0].previous_hash == genesis_hash

    for i in range(1, len(entries)):
        assert entries[i].previous_hash == entries[i - 1].entry_hash
        # Each entry hash should be unique
        assert entries[i].entry_hash != entries[i - 1].entry_hash

    # Verify the file was written with the correct number of lines
    with open(log_path, "r") as f:
        lines = [line for line in f if line.strip()]
    assert len(lines) == 5

    # Verify integrity of the complete chain
    is_valid, broken_at = logger.verify_integrity()
    assert is_valid is True
    assert broken_at is None


def test_query_by_time_range(tmp_path):
    """Query returns only entries within the specified time range."""
    log_path = str(tmp_path / "audit.jsonl")
    config = AuditConfig(log_path=log_path)
    logger = AuditLogger(config=config)

    # Record the start time
    start_time = datetime.now(timezone.utc)

    # Append entries with a small delay to ensure ordering
    logger.append(
        event_type="early",
        user_id="user-a",
        sample_id="sample-1",
        decision=AuditDecision.APPROVED,
    )

    # Small delay to create a time gap
    time.sleep(0.05)
    mid_time = datetime.now(timezone.utc)
    time.sleep(0.05)

    logger.append(
        event_type="middle",
        user_id="user-b",
        sample_id="sample-2",
        decision=AuditDecision.FLAGGED,
    )

    logger.append(
        event_type="late",
        user_id="user-c",
        sample_id="sample-3",
        decision=AuditDecision.QUARANTINED,
    )

    end_time = datetime.now(timezone.utc)

    # Query full range should return all entries
    all_entries = logger.query_by_time_range(start_time, end_time)
    assert len(all_entries) == 3

    # Query from mid_time should exclude the first entry
    later_entries = logger.query_by_time_range(mid_time, end_time)
    assert len(later_entries) == 2
    assert all(e.event_type in ("middle", "late") for e in later_entries)


def test_tamper_detection(tmp_path):
    """verify_integrity catches modifications to log entries on disk."""
    log_path = str(tmp_path / "audit.jsonl")
    config = AuditConfig(log_path=log_path)
    logger = AuditLogger(config=config)

    # Create a valid chain
    for i in range(3):
        logger.append(
            event_type="detection",
            user_id=f"user-{i}",
            sample_id=f"sample-{i}",
            score=0.7,
            decision=AuditDecision.FLAGGED,
        )

    # Chain should be valid initially
    is_valid, broken_at = logger.verify_integrity()
    assert is_valid is True
    assert broken_at is None

    # Tamper with the second entry on disk
    with open(log_path, "r") as f:
        lines = f.readlines()

    assert len(lines) == 3

    # Modify the score field in the second entry
    entry_data = json.loads(lines[1])
    entry_data["score"] = 0.99  # Changed from 0.7
    lines[1] = json.dumps(entry_data, separators=(",", ":")) + "\n"

    with open(log_path, "w") as f:
        f.writelines(lines)

    # Re-create logger to reload state from file
    logger2 = AuditLogger(config=config)

    # Verify integrity should now detect tampering at index 1
    is_valid, broken_at = logger2.verify_integrity()
    assert is_valid is False
    assert broken_at == 1
