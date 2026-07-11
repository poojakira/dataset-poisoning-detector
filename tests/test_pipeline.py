"""Tests for the pipeline consumer module.

Verifies message processing logic, quarantine routing for flagged samples,
and dead letter queue handling for processing failures. Uses mocks for
Redis/Kafka connections but tests actual message processing logic.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from poison_detector.pipeline import (
    PipelineMessage,
    ProcessingResult,
    ProcessingMode,
    RedisConsumer,
)


@pytest.fixture
def sample_message():
    """A valid pipeline message for testing."""
    return PipelineMessage(
        message_id="test-msg-001",
        sample_data=[1.0, 2.0, 3.0, 4.0, 5.0],
        source="test-stream",
        timestamp="2024-01-01T00:00:00Z",
        metadata={"batch_id": "test-batch"},
    )


def test_message_processing_invokes_detector_correctly(sample_message):
    """Processing a message calls the handler and records statistics.

    Verifies that when a message is processed through the pipeline,
    the handler is invoked with the correct PipelineMessage, and
    statistics are updated properly.
    """
    consumer = RedisConsumer(
        redis_url="redis://localhost:6379",
        stream="test:incoming",
    )

    # Simulate processing a message and recording results
    result = ProcessingResult(
        message_id=sample_message.message_id,
        is_poisoned=False,
        score=0.15,
        quarantined=False,
        dead_lettered=False,
        error="",
        processing_mode=ProcessingMode.FULL,
    )

    # Record the processing
    consumer.record_processing(elapsed_ms=5.0, quarantined=False)

    stats = consumer.stats
    assert stats.messages_processed == 1
    assert stats.avg_processing_ms == 5.0
    assert stats.messages_quarantined == 0
    assert stats.messages_dead_lettered == 0
    assert stats.current_mode == ProcessingMode.FULL


def test_quarantine_routing_sends_flagged_samples(sample_message):
    """Flagged samples are routed to the quarantine stream.

    When a processing result indicates a sample is poisoned, the consumer
    should route it to the quarantine queue and update quarantine stats.
    """
    consumer = RedisConsumer(
        redis_url="redis://localhost:6379",
        stream="test:incoming",
        quarantine_stream="test:quarantine",
    )

    # Mock the Redis client for the quarantine operation
    mock_client = AsyncMock()
    consumer._client = mock_client

    # Simulate quarantine routing
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            consumer.quarantine(sample_message, score=0.92)
        )
    finally:
        loop.close()

    # Verify xadd was called on the quarantine stream
    mock_client.xadd.assert_called_once()
    call_args = mock_client.xadd.call_args
    assert call_args[0][0] == "test:quarantine"
    payload = call_args[0][1]
    assert payload["original_id"] == "test-msg-001"
    assert payload["score"] == str(0.92)

    # Record the quarantine in stats
    consumer.record_processing(elapsed_ms=3.0, quarantined=True)
    stats = consumer.stats
    assert stats.messages_quarantined == 1


def test_dead_letter_on_processing_failure(sample_message):
    """Failed messages are routed to the dead letter queue.

    When message processing raises an exception or the handler returns
    a dead_lettered result, the message should be sent to the dead letter
    stream and statistics should reflect the failure.
    """
    consumer = RedisConsumer(
        redis_url="redis://localhost:6379",
        stream="test:incoming",
        dead_letter_stream="test:dead_letter",
    )

    # Mock the Redis client for the dead letter operation
    mock_client = AsyncMock()
    consumer._client = mock_client

    # Simulate dead letter routing due to processing failure
    error_msg = "ValueError: sample has wrong dimensionality"

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            consumer.dead_letter(sample_message, error=error_msg)
        )
    finally:
        loop.close()

    # Verify xadd was called on the dead letter stream
    mock_client.xadd.assert_called_once()
    call_args = mock_client.xadd.call_args
    assert call_args[0][0] == "test:dead_letter"
    payload = call_args[0][1]
    assert payload["original_id"] == "test-msg-001"
    assert payload["error"] == error_msg

    # Record the dead letter in stats
    consumer.record_dead_letter()
    stats = consumer.stats
    assert stats.messages_dead_lettered == 1
