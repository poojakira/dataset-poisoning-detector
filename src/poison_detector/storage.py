"""
Quarantine storage for flagged samples awaiting human review.

Provides an abstract interface (QuarantineStore) with a SQLite implementation
for development/testing and interface stubs for PostgresStore and S3Store
for production deployments.

Threat Model Assumptions:
    - Quarantined samples are untrusted data. They have been flagged as
      potentially poisoned and must not be fed back into training without
      human review and explicit resolution.
    - Storage integrity matters: if an attacker can delete quarantine records,
      they can hide evidence of a poisoning campaign. Use write-ahead logging
      (WAL) and regular backups.
    - Reviewers must authenticate before resolving quarantine entries. This
      module does not handle auth -- that is the responsibility of the API layer.

Honest Limitations:
    - SQLiteStore is single-writer. It works for development and low-throughput
      production (< 100 writes/sec) but not for multi-process deployments
      without a connection pool or WAL mode.
    - Sample data is stored as JSON text. For large samples (images, embeddings
      with thousands of dimensions), prefer S3Store with metadata in Postgres.
    - No automatic TTL or cleanup. Quarantine entries persist until explicitly
      resolved or purged. Implement a retention policy externally.
    - SQLite has no native datetime type. Timestamps are stored as ISO 8601
      strings and compared lexicographically (which works for ISO format).

Security Notes:
    - All SQL uses parameterized queries. No string interpolation in SQL.
    - Sample data is serialized via json.dumps, never pickle or eval.
    - File-based SQLite databases should have restrictive file permissions
      (0600) to prevent unauthorized access to flagged sample data.
    - The :memory: database is suitable for testing only. Data is lost on
      process exit.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ResolutionStatus(Enum):
    """Status of a quarantined sample's review."""

    PENDING = "pending"
    CONFIRMED_POISON = "confirmed_poison"
    FALSE_POSITIVE = "false_positive"
    NEEDS_INVESTIGATION = "needs_investigation"


@dataclass
class QuarantinedSample:
    """A sample stored in quarantine.

    Attributes:
        sample_id: Unique identifier for this quarantine entry.
        sample_data: The raw feature vector or data payload.
        scores: Detection scores from various methods.
        timestamp: When the sample was quarantined (UTC ISO 8601).
        source: Origin pipeline or API endpoint identifier.
        reviewer: Assigned reviewer (empty if unassigned).
        status: Current resolution status.
        resolution_notes: Human-provided notes on the resolution.
        metadata: Additional key-value metadata.
    """

    sample_id: str
    sample_data: list[float] | dict[str, Any]
    scores: dict[str, float]
    timestamp: str
    source: str = ""
    reviewer: str = ""
    status: ResolutionStatus = ResolutionStatus.PENDING
    resolution_notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class QuarantineStats:
    """Statistics about the quarantine store.

    Attributes:
        total_entries: Total quarantine entries in storage.
        pending_reviews: Entries awaiting human review.
        confirmed_poison: Entries confirmed as poisoned.
        false_positives: Entries resolved as false positives.
        oldest_pending: ISO timestamp of the oldest unresolved entry.
    """

    total_entries: int = 0
    pending_reviews: int = 0
    confirmed_poison: int = 0
    false_positives: int = 0
    oldest_pending: str = ""


class QuarantineStore(ABC):
    """Abstract interface for quarantine storage backends.

    All implementations must provide these methods. The interface is
    intentionally simple to support diverse backends (SQLite, PostgreSQL,
    S3 + metadata DB, etc.).
    """

    @abstractmethod
    def store_sample(
        self,
        sample_data: list[float] | dict[str, Any],
        scores: dict[str, float],
        timestamp: str | None = None,
        source: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Store a flagged sample in quarantine.

        Args:
            sample_data: The raw sample data (feature vector or structured data).
            scores: Detection scores from each method.
            timestamp: ISO 8601 timestamp. If None, uses current UTC time.
            source: Identifier for the data source/pipeline.
            metadata: Additional metadata to store with the sample.

        Returns:
            Unique sample_id for the quarantine entry.
        """
        ...

    @abstractmethod
    def get_sample(self, sample_id: str) -> QuarantinedSample | None:
        """Retrieve a single quarantined sample by ID.

        Args:
            sample_id: The unique identifier returned by store_sample().

        Returns:
            QuarantinedSample if found, None otherwise.
        """
        ...

    @abstractmethod
    def get_pending_reviews(self, limit: int = 100) -> list[QuarantinedSample]:
        """Get samples awaiting human review, oldest first.

        Args:
            limit: Maximum number of entries to return.

        Returns:
            List of QuarantinedSample with PENDING status.
        """
        ...

    @abstractmethod
    def resolve(
        self,
        sample_id: str,
        resolution: ResolutionStatus,
        reviewer: str = "",
        notes: str = "",
    ) -> bool:
        """Resolve a quarantine entry with a human decision.

        Args:
            sample_id: The sample to resolve.
            resolution: The resolution status.
            reviewer: Identifier of the human reviewer.
            notes: Free-text notes about the resolution.

        Returns:
            True if the sample was found and updated, False otherwise.
        """
        ...

    @abstractmethod
    def get_stats(self) -> QuarantineStats:
        """Get aggregate statistics about the quarantine store.

        Returns:
            QuarantineStats with counts and oldest pending timestamp.
        """
        ...


class SQLiteStore(QuarantineStore):
    """SQLite-backed quarantine store for development and low-throughput production.

    Uses WAL mode for better concurrent read performance and parameterized
    queries for SQL injection prevention.

    Usage:
        store = SQLiteStore(":memory:")  # for testing
        store = SQLiteStore("/var/data/quarantine.db")  # for persistence

        sample_id = store.store_sample(
            sample_data=[1.0, 2.0, 3.0],
            scores={"zscore": 0.85, "isolation": 0.72},
            source="redis-pipeline",
        )

        pending = store.get_pending_reviews()
        store.resolve(sample_id, ResolutionStatus.CONFIRMED_POISON, reviewer="alice")
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        """Initialize SQLite store and create schema.

        Args:
            db_path: Path to SQLite database file, or ":memory:" for in-memory.
        """
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_schema()

    def _create_schema(self) -> None:
        """Create the quarantine table if it does not exist."""
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                sample_id TEXT PRIMARY KEY,
                sample_data TEXT NOT NULL,
                scores TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source TEXT DEFAULT '',
                reviewer TEXT DEFAULT '',
                status TEXT DEFAULT 'pending',
                resolution_notes TEXT DEFAULT '',
                metadata TEXT DEFAULT '{}'
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_quarantine_status
            ON quarantine(status)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_quarantine_timestamp
            ON quarantine(timestamp)
        """)
        self._conn.commit()

    def store_sample(
        self,
        sample_data: list[float] | dict[str, Any],
        scores: dict[str, float],
        timestamp: str | None = None,
        source: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Store a flagged sample in quarantine.

        Args:
            sample_data: The raw sample data (feature vector or structured data).
            scores: Detection scores from each method.
            timestamp: ISO 8601 timestamp. If None, uses current UTC time.
            source: Identifier for the data source/pipeline.
            metadata: Additional metadata to store with the sample.

        Returns:
            Unique sample_id for the quarantine entry.
        """
        sample_id = str(uuid.uuid4())
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()
        if metadata is None:
            metadata = {}

        self._conn.execute(
            """
            INSERT INTO quarantine
                (sample_id, sample_data, scores, timestamp, source, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                sample_id,
                json.dumps(sample_data),
                json.dumps(scores),
                timestamp,
                source,
                json.dumps(metadata),
            ),
        )
        self._conn.commit()
        return sample_id

    def get_sample(self, sample_id: str) -> QuarantinedSample | None:
        """Retrieve a single quarantined sample by ID.

        Args:
            sample_id: The unique identifier returned by store_sample().

        Returns:
            QuarantinedSample if found, None otherwise.
        """
        cursor = self._conn.execute(
            "SELECT * FROM quarantine WHERE sample_id = ?",
            (sample_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_sample(row)

    def get_pending_reviews(self, limit: int = 100) -> list[QuarantinedSample]:
        """Get samples awaiting human review, oldest first.

        Args:
            limit: Maximum number of entries to return.

        Returns:
            List of QuarantinedSample with PENDING status.
        """
        cursor = self._conn.execute(
            """
            SELECT * FROM quarantine
            WHERE status = ?
            ORDER BY timestamp ASC
            LIMIT ?
            """,
            (ResolutionStatus.PENDING.value, limit),
        )
        return [self._row_to_sample(row) for row in cursor.fetchall()]

    def resolve(
        self,
        sample_id: str,
        resolution: ResolutionStatus,
        reviewer: str = "",
        notes: str = "",
    ) -> bool:
        """Resolve a quarantine entry with a human decision.

        Args:
            sample_id: The sample to resolve.
            resolution: The resolution status.
            reviewer: Identifier of the human reviewer.
            notes: Free-text notes about the resolution.

        Returns:
            True if the sample was found and updated, False otherwise.
        """
        cursor = self._conn.execute(
            """
            UPDATE quarantine
            SET status = ?, reviewer = ?, resolution_notes = ?
            WHERE sample_id = ?
            """,
            (resolution.value, reviewer, notes, sample_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def get_stats(self) -> QuarantineStats:
        """Get aggregate statistics about the quarantine store.

        Returns:
            QuarantineStats with counts and oldest pending timestamp.
        """
        cursor = self._conn.execute("SELECT COUNT(*) FROM quarantine")
        total = cursor.fetchone()[0]

        cursor = self._conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE status = ?",
            (ResolutionStatus.PENDING.value,),
        )
        pending = cursor.fetchone()[0]

        cursor = self._conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE status = ?",
            (ResolutionStatus.CONFIRMED_POISON.value,),
        )
        confirmed = cursor.fetchone()[0]

        cursor = self._conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE status = ?",
            (ResolutionStatus.FALSE_POSITIVE.value,),
        )
        false_pos = cursor.fetchone()[0]

        oldest_pending = ""
        cursor = self._conn.execute(
            """
            SELECT MIN(timestamp) FROM quarantine WHERE status = ?
            """,
            (ResolutionStatus.PENDING.value,),
        )
        row = cursor.fetchone()
        if row and row[0]:
            oldest_pending = row[0]

        return QuarantineStats(
            total_entries=total,
            pending_reviews=pending,
            confirmed_poison=confirmed,
            false_positives=false_pos,
            oldest_pending=oldest_pending,
        )

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    @staticmethod
    def _row_to_sample(row: sqlite3.Row) -> QuarantinedSample:
        """Convert a database row to a QuarantinedSample dataclass."""
        return QuarantinedSample(
            sample_id=row["sample_id"],
            sample_data=json.loads(row["sample_data"]),
            scores=json.loads(row["scores"]),
            timestamp=row["timestamp"],
            source=row["source"],
            reviewer=row["reviewer"],
            status=ResolutionStatus(row["status"]),
            resolution_notes=row["resolution_notes"],
            metadata=json.loads(row["metadata"]),
        )


class PostgresStore(QuarantineStore):
    """PostgreSQL quarantine store for production deployments.

    Interface stub - not yet implemented. Requires asyncpg or psycopg3.

    Intended for multi-process, high-throughput deployments where SQLite's
    single-writer limitation is insufficient.
    """

    def __init__(self, connection_url: str) -> None:
        """Initialize with a PostgreSQL connection URL.

        Args:
            connection_url: PostgreSQL DSN (e.g., postgresql://user:pass@host/db).

        Raises:
            NotImplementedError: This backend is not yet implemented.
        """
        raise NotImplementedError(
            "PostgresStore is not yet implemented. Use SQLiteStore for development "
            "or contribute a PostgreSQL implementation."
        )

    def store_sample(
        self,
        sample_data: list[float] | dict[str, Any],
        scores: dict[str, float],
        timestamp: str | None = None,
        source: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        raise NotImplementedError("PostgresStore is not yet implemented.")

    def get_sample(self, sample_id: str) -> QuarantinedSample | None:
        raise NotImplementedError("PostgresStore is not yet implemented.")

    def get_pending_reviews(self, limit: int = 100) -> list[QuarantinedSample]:
        raise NotImplementedError("PostgresStore is not yet implemented.")

    def resolve(
        self,
        sample_id: str,
        resolution: ResolutionStatus,
        reviewer: str = "",
        notes: str = "",
    ) -> bool:
        raise NotImplementedError("PostgresStore is not yet implemented.")

    def get_stats(self) -> QuarantineStats:
        raise NotImplementedError("PostgresStore is not yet implemented.")


class S3Store(QuarantineStore):
    """S3-backed quarantine store for large samples (images, embeddings).

    Interface stub - not yet implemented. Requires boto3.

    Design: stores raw sample data in S3 with metadata (scores, status) in
    a sidecar database (DynamoDB or PostgreSQL). Suitable for multi-modal
    data where individual samples may be megabytes.
    """

    def __init__(self, bucket: str, prefix: str = "quarantine/") -> None:
        """Initialize with an S3 bucket and key prefix.

        Args:
            bucket: S3 bucket name.
            prefix: Key prefix for quarantine objects.

        Raises:
            NotImplementedError: This backend is not yet implemented.
        """
        raise NotImplementedError(
            "S3Store is not yet implemented. Use SQLiteStore for development "
            "or contribute an S3 implementation."
        )

    def store_sample(
        self,
        sample_data: list[float] | dict[str, Any],
        scores: dict[str, float],
        timestamp: str | None = None,
        source: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        raise NotImplementedError("S3Store is not yet implemented.")

    def get_sample(self, sample_id: str) -> QuarantinedSample | None:
        raise NotImplementedError("S3Store is not yet implemented.")

    def get_pending_reviews(self, limit: int = 100) -> list[QuarantinedSample]:
        raise NotImplementedError("S3Store is not yet implemented.")

    def resolve(
        self,
        sample_id: str,
        resolution: ResolutionStatus,
        reviewer: str = "",
        notes: str = "",
    ) -> bool:
        raise NotImplementedError("S3Store is not yet implemented.")

    def get_stats(self) -> QuarantineStats:
        raise NotImplementedError("S3Store is not yet implemented.")
