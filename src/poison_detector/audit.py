"""
Immutable audit trail with tamper detection for SOC2/ISO27001 compliance.

Provides an append-only structured log in JSON Lines format with a
blockchain-lite hash chain for tamper evidence. Every detection event
records who, what, when, score, decision, and sample_hash. The log is
queryable by time range, sample ID, user, and decision type, and
exportable for compliance audits.

Threat Model Assumptions:
    - The audit log file resides on storage controlled by the deployment
      infrastructure. File-level access controls (0600, dedicated service
      account) prevent unauthorized direct modification.
    - An attacker who gains write access to the log file can append entries
      but cannot silently modify or delete existing entries without breaking
      the hash chain. The verify_integrity() method detects any such
      tampering.
    - The hash chain uses SHA-256. An attacker who can find SHA-256
      collisions (computationally infeasible as of 2024) could forge
      entries. This is acceptable for audit purposes but not for
      cryptographic non-repudiation against nation-state adversaries.
    - Concurrent writers are serialized via file locking (fcntl/flock).
      A single audit log file should be written by one logical service;
      multiple replicas should write to separate files and merge during
      export.

Honest Limitations:
    - The hash chain provides tamper detection, not tamper prevention. An
      attacker with file access can destroy the log entirely (deletion).
      Use append-only filesystem features (chattr +a on Linux) or remote
      log shipping (syslog, CloudWatch Logs) for stronger guarantees.
    - File locking is advisory on most Unix systems. A malicious process
      that ignores locks can corrupt the file. This protects against
      accidental concurrent writes, not adversarial corruption.
    - Query methods load entries into memory. For logs with millions of
      entries, use a dedicated log analytics system (Elasticsearch, Loki)
      rather than querying the raw file.
    - JSON Lines format means each entry is self-contained but the file
      grows unbounded. Implement log rotation externally (logrotate) and
      use export_for_audit() to archive rotated segments.
    - The retention policy is advisory metadata. Actual enforcement
      (deletion of entries older than the retention period) must be
      handled by an external process to maintain the append-only property.

Security Notes:
    - NEVER modify existing entries. The append() method only writes to
      the end of the file. Any in-place modification breaks the chain.
    - Entry hashes incorporate the previous entry hash, creating a linked
      chain. Verification traverses the entire chain from genesis.
    - Timestamps use UTC ISO 8601 format for unambiguous ordering across
      time zones. Clock skew between services can cause out-of-order
      timestamps but does not break the hash chain.
    - The genesis entry (first in the chain) uses a well-known previous
      hash of all zeros. This is not secret and does not weaken security.
    - File permissions should be set to 0600 (owner read/write only).
      This module does not enforce permissions; the deployment must.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GENESIS_PREVIOUS_HASH = "0" * 64  # SHA-256 of "nothing" for the first entry
_DEFAULT_RETENTION_YEARS = 7  # SOC2/ISO27001 default retention


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------


class AuditDecision(Enum):
    """Possible decisions recorded in the audit trail."""

    FLAGGED = "flagged"
    QUARANTINED = "quarantined"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    REVIEWED = "reviewed"
    EXPORTED = "exported"


class ExportFormat(Enum):
    """Supported export formats for compliance audits."""

    JSON_LINES = "json_lines"
    JSON_ARRAY = "json_array"
    CSV = "csv"


@dataclass
class AuditEntry:
    """A single immutable audit trail entry.

    Attributes:
        entry_id: Unique identifier for this entry (UUID4).
        timestamp: UTC ISO 8601 timestamp of the event.
        event_type: Category of the audit event.
        user_id: Identifier of the user/service that triggered the event.
        sample_id: Identifier of the sample involved (if applicable).
        sample_hash: SHA-256 hash of the sample data for integrity reference.
        score: Detection score associated with the event (0.0 if not applicable).
        decision: The decision made (flagged, quarantined, approved, etc.).
        metadata: Additional context as key-value pairs.
        previous_hash: SHA-256 hash of the previous entry (chain link).
        entry_hash: SHA-256 hash of this entry (computed over all other fields).
    """

    entry_id: str
    timestamp: str
    event_type: str
    user_id: str
    sample_id: str
    sample_hash: str
    score: float
    decision: str
    metadata: dict[str, Any]
    previous_hash: str
    entry_hash: str


@dataclass
class AuditConfig:
    """Configuration for the audit logger.

    Attributes:
        log_path: Path to the JSON Lines audit log file.
        retention_years: Number of years to retain audit entries.
        max_metadata_size: Maximum size in bytes for the metadata field.
        flush_on_write: Whether to flush the file after each write.
    """

    log_path: str = "audit_trail.jsonl"
    retention_years: int = _DEFAULT_RETENTION_YEARS
    max_metadata_size: int = 4096
    flush_on_write: bool = True


# ---------------------------------------------------------------------------
# Core Implementation
# ---------------------------------------------------------------------------


class AuditLogger:
    """Append-only audit trail with hash chain tamper detection.

    Implements an immutable, tamper-evident log suitable for SOC2 and
    ISO27001 compliance. Each entry is chained to the previous via
    SHA-256 hashes, forming a blockchain-lite structure that detects
    any modification, insertion, or deletion of entries.

    Usage:
        logger = AuditLogger(AuditConfig(log_path="/var/log/audit.jsonl"))

        # Record an event
        entry = logger.append(
            event_type="detection",
            user_id="service:pipeline-01",
            sample_id="sample-abc-123",
            sample_hash="sha256:abcdef...",
            score=0.87,
            decision=AuditDecision.FLAGGED,
            metadata={"method": "isolation_forest", "threshold": 0.75},
        )

        # Verify integrity
        is_valid, broken_at = logger.verify_integrity()
        assert is_valid

        # Query for compliance
        entries = logger.query_by_time_range(start, end)
        export_data = logger.export_for_audit(start, end, ExportFormat.JSON_ARRAY)
    """

    def __init__(self, config: AuditConfig | None = None) -> None:
        """Initialize the audit logger.

        Args:
            config: Audit configuration. Uses defaults if None.
        """
        self._config = config or AuditConfig()
        self._lock = threading.Lock()
        self._last_hash: str | None = None

        # Initialize last hash from existing log
        self._last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        """Recover the last entry hash from an existing log file.

        Reads the last line of the log file to recover the chain state.
        If the file does not exist or is empty, returns the genesis hash.

        Returns:
            The hash of the last entry, or genesis hash if no entries exist.
        """
        if not os.path.exists(self._config.log_path):
            return _GENESIS_PREVIOUS_HASH

        try:
            last_line = ""
            with open(self._config.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped

            if not last_line:
                return _GENESIS_PREVIOUS_HASH

            entry_data = json.loads(last_line)
            return entry_data.get("entry_hash", _GENESIS_PREVIOUS_HASH)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to recover last hash from audit log: {e}")
            return _GENESIS_PREVIOUS_HASH

    def append(
        self,
        event_type: str,
        user_id: str,
        sample_id: str = "",
        sample_hash: str = "",
        score: float = 0.0,
        decision: AuditDecision | str = AuditDecision.FLAGGED,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Append a new audit entry to the log.

        Creates a new entry with auto-generated ID and timestamp, chains
        it to the previous entry via SHA-256 hash, and atomically appends
        it to the log file.

        Args:
            event_type: Category of the event (e.g., "detection", "review").
            user_id: Identifier of the user or service triggering the event.
            sample_id: Identifier of the sample involved.
            sample_hash: SHA-256 hash of the sample data.
            score: Detection score (0.0 if not applicable).
            decision: The decision made. Can be AuditDecision enum or string.
            metadata: Additional context. Truncated if exceeds max size.

        Returns:
            The created AuditEntry with computed hash chain.

        Raises:
            OSError: If the log file cannot be written.
        """
        if metadata is None:
            metadata = {}

        # Validate metadata size
        metadata_json = json.dumps(metadata, separators=(",", ":"))
        if len(metadata_json.encode("utf-8")) > self._config.max_metadata_size:
            metadata = {"_truncated": True, "original_keys": list(metadata.keys())}

        # Resolve decision to string
        decision_str = decision.value if isinstance(decision, AuditDecision) else str(decision)

        with self._lock:
            # Generate entry fields
            entry_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc).isoformat()
            previous_hash = self._last_hash or _GENESIS_PREVIOUS_HASH

            # Compute entry hash over all fields (excluding entry_hash itself)
            entry_hash = self._compute_entry_hash(
                entry_id=entry_id,
                timestamp=timestamp,
                event_type=event_type,
                user_id=user_id,
                sample_id=sample_id,
                sample_hash=sample_hash,
                score=score,
                decision=decision_str,
                metadata=metadata,
                previous_hash=previous_hash,
            )

            entry = AuditEntry(
                entry_id=entry_id,
                timestamp=timestamp,
                event_type=event_type,
                user_id=user_id,
                sample_id=sample_id,
                sample_hash=sample_hash,
                score=score,
                decision=decision_str,
                metadata=metadata,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
            )

            # Write to file with file locking
            self._write_entry(entry)

            # Update chain state
            self._last_hash = entry_hash

        return entry

    def query_by_time_range(
        self,
        start: datetime | str,
        end: datetime | str,
    ) -> list[AuditEntry]:
        """Query audit entries within a time range.

        Args:
            start: Start of the time range (inclusive). ISO 8601 string or datetime.
            end: End of the time range (inclusive). ISO 8601 string or datetime.

        Returns:
            List of AuditEntry objects within the specified range.
        """
        start_str = self._normalize_timestamp(start)
        end_str = self._normalize_timestamp(end)

        entries = self._read_all_entries()
        return [
            e for e in entries
            if start_str <= e.timestamp <= end_str
        ]

    def query_by_sample_id(self, sample_id: str) -> list[AuditEntry]:
        """Query audit entries for a specific sample.

        Args:
            sample_id: The sample identifier to search for.

        Returns:
            List of AuditEntry objects for the specified sample.
        """
        entries = self._read_all_entries()
        return [e for e in entries if e.sample_id == sample_id]

    def query_by_user(self, user_id: str) -> list[AuditEntry]:
        """Query audit entries by user identifier.

        Args:
            user_id: The user identifier to search for.

        Returns:
            List of AuditEntry objects for the specified user.
        """
        entries = self._read_all_entries()
        return [e for e in entries if e.user_id == user_id]

    def query_by_decision(self, decision: AuditDecision | str) -> list[AuditEntry]:
        """Query audit entries by decision type.

        Args:
            decision: The decision to filter by. Can be AuditDecision or string.

        Returns:
            List of AuditEntry objects with the specified decision.
        """
        decision_str = decision.value if isinstance(decision, AuditDecision) else str(decision)
        entries = self._read_all_entries()
        return [e for e in entries if e.decision == decision_str]

    def verify_integrity(self) -> tuple[bool, int | None]:
        """Verify the hash chain integrity of the entire audit log.

        Traverses the log from the first entry, recomputing each entry's
        hash and verifying it matches the stored hash and that the
        previous_hash field correctly references the preceding entry.

        Returns:
            Tuple of (is_valid, broken_at_index). If valid, broken_at_index
            is None. If tampered, broken_at_index is the 0-based index of
            the first entry where the chain is broken.
        """
        entries = self._read_all_entries()
        if not entries:
            return True, None

        expected_previous_hash = _GENESIS_PREVIOUS_HASH

        for i, entry in enumerate(entries):
            # Verify previous_hash chain link
            if entry.previous_hash != expected_previous_hash:
                logger.warning(
                    f"Audit chain broken at index {i}: "
                    f"expected previous_hash={expected_previous_hash[:16]}..., "
                    f"got={entry.previous_hash[:16]}..."
                )
                return False, i

            # Recompute entry hash and verify
            computed_hash = self._compute_entry_hash(
                entry_id=entry.entry_id,
                timestamp=entry.timestamp,
                event_type=entry.event_type,
                user_id=entry.user_id,
                sample_id=entry.sample_id,
                sample_hash=entry.sample_hash,
                score=entry.score,
                decision=entry.decision,
                metadata=entry.metadata,
                previous_hash=entry.previous_hash,
            )

            if computed_hash != entry.entry_hash:
                logger.warning(
                    f"Audit entry hash mismatch at index {i}: "
                    f"computed={computed_hash[:16]}..., "
                    f"stored={entry.entry_hash[:16]}..."
                )
                return False, i

            expected_previous_hash = entry.entry_hash

        return True, None

    def export_for_audit(
        self,
        start: datetime | str,
        end: datetime | str,
        format: ExportFormat | str = ExportFormat.JSON_LINES,
    ) -> str:
        """Export audit entries for compliance audits.

        Exports entries within the specified time range in the requested
        format, suitable for submission to auditors.

        Args:
            start: Start of the export range (inclusive).
            end: End of the export range (inclusive).
            format: Output format (json_lines, json_array, or csv).

        Returns:
            Formatted string containing the exported audit data.
        """
        entries = self.query_by_time_range(start, end)

        # Resolve format
        if isinstance(format, str):
            format = ExportFormat(format)

        if format == ExportFormat.JSON_LINES:
            return self._export_json_lines(entries)
        elif format == ExportFormat.JSON_ARRAY:
            return self._export_json_array(entries)
        elif format == ExportFormat.CSV:
            return self._export_csv(entries)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    @property
    def config(self) -> AuditConfig:
        """The current audit configuration."""
        return self._config

    @property
    def entry_count(self) -> int:
        """Total number of entries in the audit log."""
        if not os.path.exists(self._config.log_path):
            return 0
        count = 0
        with open(self._config.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1
        return count

    # -----------------------------------------------------------------------
    # Private Methods
    # -----------------------------------------------------------------------

    def _compute_entry_hash(
        self,
        entry_id: str,
        timestamp: str,
        event_type: str,
        user_id: str,
        sample_id: str,
        sample_hash: str,
        score: float,
        decision: str,
        metadata: dict[str, Any],
        previous_hash: str,
    ) -> str:
        """Compute SHA-256 hash over all entry fields for chain integrity.

        The hash is computed over a deterministic JSON serialization of
        all fields (excluding entry_hash itself). This ensures any
        modification to any field will change the hash.

        Args:
            All entry fields except entry_hash.

        Returns:
            Hex-encoded SHA-256 hash string.
        """
        hash_input = json.dumps(
            {
                "entry_id": entry_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "user_id": user_id,
                "sample_id": sample_id,
                "sample_hash": sample_hash,
                "score": score,
                "decision": decision,
                "metadata": metadata,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hashlib.sha256(hash_input).hexdigest()

    def _write_entry(self, entry: AuditEntry) -> None:
        """Write an entry to the log file with file locking.

        Uses advisory file locking (fcntl.flock) to serialize concurrent
        writes from multiple threads or processes.

        Args:
            entry: The AuditEntry to write.

        Raises:
            OSError: If the file cannot be opened or written.
        """
        entry_dict = asdict(entry)
        line = json.dumps(entry_dict, separators=(",", ":")) + "\n"

        # Ensure parent directory exists
        log_dir = os.path.dirname(self._config.log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        with open(self._config.log_path, "a", encoding="utf-8") as f:
            # Acquire exclusive lock for writing
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(line)
                if self._config.flush_on_write:
                    f.flush()
                    os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def _read_all_entries(self) -> list[AuditEntry]:
        """Read all entries from the audit log file.

        Returns:
            List of AuditEntry objects in chronological order.
        """
        if not os.path.exists(self._config.log_path):
            return []

        entries: list[AuditEntry] = []

        with open(self._config.log_path, "r", encoding="utf-8") as f:
            # Shared lock for reading
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                for line_num, line in enumerate(f, 1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        data = json.loads(stripped)
                        entries.append(AuditEntry(
                            entry_id=data["entry_id"],
                            timestamp=data["timestamp"],
                            event_type=data["event_type"],
                            user_id=data["user_id"],
                            sample_id=data["sample_id"],
                            sample_hash=data["sample_hash"],
                            score=data["score"],
                            decision=data["decision"],
                            metadata=data["metadata"],
                            previous_hash=data["previous_hash"],
                            entry_hash=data["entry_hash"],
                        ))
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.warning(
                            f"Skipping malformed audit entry at line {line_num}: {e}"
                        )
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        return entries

    def _export_json_lines(self, entries: list[AuditEntry]) -> str:
        """Export entries as JSON Lines format.

        Args:
            entries: Entries to export.

        Returns:
            JSON Lines formatted string.
        """
        lines = []
        for entry in entries:
            lines.append(json.dumps(asdict(entry), separators=(",", ":")))
        return "\n".join(lines) + ("\n" if lines else "")

    def _export_json_array(self, entries: list[AuditEntry]) -> str:
        """Export entries as a JSON array.

        Args:
            entries: Entries to export.

        Returns:
            JSON array formatted string.
        """
        return json.dumps(
            [asdict(entry) for entry in entries],
            indent=2,
        )

    def _export_csv(self, entries: list[AuditEntry]) -> str:
        """Export entries as CSV format.

        Args:
            entries: Entries to export.

        Returns:
            CSV formatted string with header row.
        """
        import csv
        import io

        output = io.StringIO()
        fieldnames = [
            "entry_id",
            "timestamp",
            "event_type",
            "user_id",
            "sample_id",
            "sample_hash",
            "score",
            "decision",
            "metadata",
            "previous_hash",
            "entry_hash",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for entry in entries:
            row = asdict(entry)
            # Serialize metadata dict to JSON string for CSV
            row["metadata"] = json.dumps(row["metadata"], separators=(",", ":"))
            writer.writerow(row)

        return output.getvalue()

    @staticmethod
    def _normalize_timestamp(ts: datetime | str) -> str:
        """Normalize a timestamp to ISO 8601 string for comparison.

        Args:
            ts: A datetime object or ISO 8601 string.

        Returns:
            ISO 8601 formatted string.
        """
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts.isoformat()
        return str(ts)
