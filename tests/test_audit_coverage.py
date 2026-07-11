"""Coverage tests for the immutable audit trail.

Covers the query-by-sample/user/decision helpers, all three export formats,
metadata truncation, entry_count / config properties, last-hash recovery
across logger instances, and malformed-line handling.
"""

import json
import os

from datetime import datetime, timedelta, timezone

from poison_detector.audit import (
    AuditConfig,
    AuditDecision,
    AuditLogger,
    ExportFormat,
)


def _logger(tmp_path, **kw):
    return AuditLogger(config=AuditConfig(log_path=str(tmp_path / "audit.jsonl"), **kw))


def test_query_helpers(tmp_path):
    """query_by_sample_id / user / decision filter the log correctly."""
    log = _logger(tmp_path)
    log.append(event_type="d", user_id="alice", sample_id="s1", decision=AuditDecision.FLAGGED)
    log.append(event_type="d", user_id="bob", sample_id="s2", decision=AuditDecision.APPROVED)
    log.append(event_type="d", user_id="alice", sample_id="s1", decision=AuditDecision.QUARANTINED)

    assert len(log.query_by_sample_id("s1")) == 2
    assert len(log.query_by_user("bob")) == 1
    assert len(log.query_by_decision(AuditDecision.APPROVED)) == 1
    assert len(log.query_by_decision("flagged")) == 1


def test_export_formats(tmp_path):
    """export_for_audit renders json_lines, json_array, and csv."""
    log = _logger(tmp_path)
    start = datetime.now(timezone.utc) - timedelta(seconds=1)
    log.append(event_type="d", user_id="u", sample_id="s", score=0.5,
               decision=AuditDecision.FLAGGED, metadata={"m": "v"})
    end = datetime.now(timezone.utc) + timedelta(seconds=1)

    jl = log.export_for_audit(start, end, ExportFormat.JSON_LINES)
    assert jl.strip().startswith("{") and "entry_hash" in jl

    arr = log.export_for_audit(start, end, "json_array")
    parsed = json.loads(arr)
    assert isinstance(parsed, list) and parsed[0]["user_id"] == "u"

    csv_out = log.export_for_audit(start, end, ExportFormat.CSV)
    assert "entry_id,timestamp" in csv_out.splitlines()[0]
    assert "\"m\"" in csv_out or "m" in csv_out


def test_export_empty_range_json_lines(tmp_path):
    """Exporting an empty range yields an empty JSON Lines string."""
    log = _logger(tmp_path)
    past = datetime.now(timezone.utc) - timedelta(days=2)
    older = past - timedelta(days=1)
    assert log.export_for_audit(older, past, ExportFormat.JSON_LINES) == ""


def test_metadata_truncation(tmp_path):
    """Oversized metadata is replaced with a truncation marker."""
    log = _logger(tmp_path, max_metadata_size=32)
    big = {"k": "x" * 500}
    entry = log.append(event_type="d", user_id="u", metadata=big)
    assert entry.metadata.get("_truncated") is True
    assert "original_keys" in entry.metadata


def test_entry_count_and_config_properties(tmp_path):
    """entry_count reflects appended entries; config exposes the settings."""
    log = _logger(tmp_path, retention_years=3)
    assert log.entry_count == 0
    log.append(event_type="d", user_id="u")
    log.append(event_type="d", user_id="u2")
    assert log.entry_count == 2
    assert log.config.retention_years == 3


def test_last_hash_recovery_continues_chain(tmp_path):
    """A new logger instance recovers the last hash and continues the chain."""
    cfg = AuditConfig(log_path=str(tmp_path / "audit.jsonl"))
    log1 = AuditLogger(config=cfg)
    e1 = log1.append(event_type="d", user_id="u")

    log2 = AuditLogger(config=cfg)
    e2 = log2.append(event_type="d", user_id="u2")
    # The second logger chained onto the first logger's last entry
    assert e2.previous_hash == e1.entry_hash

    is_valid, broken = log2.verify_integrity()
    assert is_valid is True and broken is None


def test_malformed_lines_are_skipped(tmp_path):
    """Malformed / blank lines in the log file are ignored on read."""
    path = str(tmp_path / "audit.jsonl")
    log = AuditLogger(config=AuditConfig(log_path=path))
    log.append(event_type="d", user_id="u", sample_id="s")

    with open(path, "a") as f:
        f.write("\n")               # blank
        f.write("not json at all\n")  # malformed
        f.write(json.dumps({"missing": "fields"}) + "\n")  # missing keys

    # Only the one valid entry is returned
    assert len(log.query_by_user("u")) == 1


def test_recover_last_hash_from_corrupt_tail(tmp_path):
    """If the tail line is unparseable, recovery falls back to genesis hash."""
    path = str(tmp_path / "audit.jsonl")
    with open(path, "w") as f:
        f.write("garbage-not-json\n")
    log = AuditLogger(config=AuditConfig(log_path=path))
    # Genesis hash means the next appended entry starts a fresh chain
    entry = log.append(event_type="d", user_id="u")
    assert entry.previous_hash == "0" * 64


def test_verify_integrity_empty_log(tmp_path):
    """An empty (nonexistent) log verifies as valid."""
    log = _logger(tmp_path)
    is_valid, broken = log.verify_integrity()
    assert is_valid is True and broken is None
