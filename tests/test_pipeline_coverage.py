"""Additional coverage tests for the pipeline consumer module.

Exercises the async consume loops (valid/quarantine/dead-letter/handler-error
paths), backpressure engagement and recovery, connect/disconnect error and
success paths, and the Kafka in-parse/routing helpers. Redis/Kafka clients are
replaced with async mocks so the real message-processing logic runs without a
live broker.
"""

import asyncio
import json
import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from poison_detector.pipeline import (
    KafkaConsumer,
    PipelineConsumer,
    PipelineMessage,
    PipelineStats,
    ProcessingMode,
    ProcessingResult,
    RedisConsumer,
)


def _run(coro):
    """Run a coroutine on a fresh event loop and return its result."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# --------------------------------------------------------------------------
# Backpressure state machine
# --------------------------------------------------------------------------


def test_backpressure_engages_and_recovers():
    """update_backpressure switches to statistical-only above threshold and
    recovers to full mode once the queue drains below the recovery point."""
    consumer = RedisConsumer(
        redis_url="", backpressure_threshold=100, backpressure_recovery=50
    )
    assert consumer.processing_mode == ProcessingMode.FULL

    # Below threshold -> stays FULL
    consumer.update_backpressure(80)
    assert consumer.processing_mode == ProcessingMode.FULL

    # Above threshold -> engage statistical-only
    consumer.update_backpressure(150)
    assert consumer.processing_mode == ProcessingMode.STATISTICAL_ONLY

    # Between recovery and threshold -> stays degraded
    consumer.update_backpressure(70)
    assert consumer.processing_mode == ProcessingMode.STATISTICAL_ONLY

    # Below recovery -> back to FULL
    consumer.update_backpressure(10)
    assert consumer.processing_mode == ProcessingMode.FULL
    assert consumer.stats.queue_depth == 10


def test_stats_average_processing_time():
    """stats.avg_processing_ms is the mean of recorded processing durations."""
    consumer = RedisConsumer(redis_url="")
    consumer.record_processing(10.0)
    consumer.record_processing(20.0, quarantined=True)
    stats = consumer.stats
    assert stats.messages_processed == 2
    assert stats.messages_quarantined == 1
    assert stats.avg_processing_ms == 15.0


def test_stop_sets_running_false():
    """stop() flips the running flag so the consume loop exits."""
    consumer = RedisConsumer(redis_url="")
    consumer._running = True
    consumer.stop()
    assert consumer._running is False


# --------------------------------------------------------------------------
# RedisConsumer.consume loop
# --------------------------------------------------------------------------


def test_redis_consume_processes_all_paths():
    """The Redis consume loop routes each message to the correct outcome:
    quarantine, normal processing, handler-returned dead-letter, handler
    exception dead-letter, and unparseable raw dead-letter."""
    consumer = RedisConsumer(redis_url="", stream="samples:incoming")
    client = AsyncMock()

    batch = [
        (
            "samples:incoming",
            [
                ("1-0", {"sample_data": json.dumps([1.0, 2.0]), "source": "s"}),
                ("2-0", {}),  # no sample_data -> unparseable
                ("3-0", {"sample_data": json.dumps([3.0])}),  # handler raises
                ("4-0", {"sample_data": json.dumps([4.0])}),  # handler dead-letters
                ("5-0", {"sample_data": json.dumps([5.0])}),  # normal processed
            ],
        )
    ]

    call_count = {"n": 0}

    async def fake_xreadgroup(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return batch
        consumer.stop()
        return []

    client.xreadgroup = fake_xreadgroup
    client.xinfo_stream = AsyncMock(return_value={"length": 0})
    consumer._client = client

    async def handler(msg: PipelineMessage) -> ProcessingResult:
        data = msg.sample_data
        if data == [1.0, 2.0]:
            return ProcessingResult(message_id=msg.message_id, quarantined=True, score=0.9)
        if data == [3.0]:
            raise RuntimeError("boom")
        if data == [4.0]:
            return ProcessingResult(message_id=msg.message_id, dead_lettered=True, error="bad")
        return ProcessingResult(message_id=msg.message_id)

    _run(consumer.consume(handler, batch_size=10))

    stats = consumer.stats
    assert stats.messages_consumed == 5
    assert stats.messages_quarantined == 1
    # msg 2 (unparseable), 3 (raise), 4 (dead_lettered) all dead lettered
    assert stats.messages_dead_lettered == 3
    # msg 1 (quarantine) + msg 5 (normal) processed
    assert stats.messages_processed == 2
    # Both quarantine and dead-letter stream writes occurred
    assert client.xadd.await_count >= 4
    assert client.xack.await_count == 5


def test_redis_consume_requires_connection():
    """consume() raises if called before connect()."""
    consumer = RedisConsumer(redis_url="")
    consumer._client = None
    with pytest.raises(RuntimeError, match="Not connected"):
        _run(consumer.consume(AsyncMock()))


def test_redis_consume_backpressure_on_empty_batch():
    """When no messages are available the loop polls queue depth and updates
    backpressure state."""
    consumer = RedisConsumer(
        redis_url="", backpressure_threshold=100, backpressure_recovery=50
    )
    client = AsyncMock()

    async def fake_xreadgroup(*args, **kwargs):
        consumer.stop()
        return []

    client.xreadgroup = fake_xreadgroup
    client.xinfo_stream = AsyncMock(return_value={"length": 500})
    consumer._client = client

    _run(consumer.consume(AsyncMock(), batch_size=5))
    assert consumer.processing_mode == ProcessingMode.STATISTICAL_ONLY


# --------------------------------------------------------------------------
# RedisConsumer connect / disconnect
# --------------------------------------------------------------------------


def test_redis_connect_import_error():
    """connect() raises a clear ImportError when the redis package is absent."""
    consumer = RedisConsumer(redis_url="redis://localhost:6379")
    with patch.dict(sys.modules, {"redis.asyncio": None}):
        with pytest.raises(ImportError, match="redis package required"):
            _run(consumer.connect())


def test_redis_connect_success_and_disconnect():
    """connect() creates a consumer group then disconnect() closes the client."""
    consumer = RedisConsumer(redis_url="redis://localhost:6379")
    fake_client = AsyncMock()
    with patch("redis.asyncio.from_url", MagicMock(return_value=fake_client)):
        _run(consumer.connect())
    assert consumer._client is fake_client
    fake_client.xgroup_create.assert_awaited()

    _run(consumer.disconnect())
    assert consumer._client is None
    fake_client.aclose.assert_awaited()


def test_redis_connect_connection_error():
    """A failure constructing the client surfaces as ConnectionError."""
    consumer = RedisConsumer(redis_url="redis://localhost:6379")
    with patch("redis.asyncio.from_url", MagicMock(side_effect=RuntimeError("no server"))):
        with pytest.raises(ConnectionError, match="Failed to connect to Redis"):
            _run(consumer.connect())


def test_redis_acknowledge_and_parse_bad_json():
    """acknowledge() calls xack; _parse_message returns None on malformed JSON."""
    consumer = RedisConsumer(redis_url="")
    client = AsyncMock()
    consumer._client = client
    _run(consumer.acknowledge("9-0"))
    client.xack.assert_awaited_once()

    assert RedisConsumer._parse_message("1-0", {"sample_data": "not-json{"}) is None
    parsed = RedisConsumer._parse_message(
        "1-0", {"sample_data": "[1,2]", "source": "x", "extra": "m"}
    )
    assert parsed is not None
    assert parsed.metadata == {"extra": "m"}


# --------------------------------------------------------------------------
# KafkaConsumer
# --------------------------------------------------------------------------


def test_kafka_connect_import_error():
    """KafkaConsumer.connect raises ImportError because aiokafka is absent."""
    consumer = KafkaConsumer(bootstrap_servers="localhost:9092")
    with pytest.raises(ImportError, match="aiokafka package required"):
        _run(consumer.connect())


def test_kafka_consume_requires_connection():
    """consume() raises if the Kafka consumer has not been started."""
    consumer = KafkaConsumer()
    with pytest.raises(RuntimeError, match="Not connected"):
        _run(consumer.consume(AsyncMock()))


def test_kafka_consume_processes_batch():
    """The Kafka consume loop processes a batch: quarantine, dead-letter, error,
    and unparseable messages, then commits offsets."""
    consumer = KafkaConsumer(topic="training-samples")
    kafka_consumer = MagicMock()
    producer = AsyncMock()

    def make_msg(value):
        return types.SimpleNamespace(value=value, topic="training-samples", partition=0, offset=1)

    msgs = [
        make_msg({"sample_data": [1.0, 2.0]}),  # quarantine
        make_msg({"sample_data": [4.0]}),  # dead_lettered
        make_msg({"sample_data": [3.0]}),  # handler raises
        make_msg("not-a-dict"),  # unparseable
        make_msg({"no_sample": 1}),  # missing sample_data -> unparseable
    ]

    call_count = {"n": 0}

    async def fake_getmany(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return {"tp0": msgs}
        consumer.stop()
        return {}

    kafka_consumer.getmany = fake_getmany
    kafka_consumer.commit = AsyncMock()
    kafka_consumer.assignment = MagicMock(return_value=set())
    consumer._consumer = kafka_consumer
    consumer._producer = producer

    async def handler(msg: PipelineMessage) -> ProcessingResult:
        data = msg.sample_data
        if data == [1.0, 2.0]:
            return ProcessingResult(message_id=msg.message_id, quarantined=True, score=0.8)
        if data == [4.0]:
            return ProcessingResult(message_id=msg.message_id, dead_lettered=True, error="bad")
        if data == [3.0]:
            raise RuntimeError("boom")
        return ProcessingResult(message_id=msg.message_id)

    _run(consumer.consume(handler, batch_size=10))

    stats = consumer.stats
    assert stats.messages_consumed == 5
    assert stats.messages_quarantined == 1
    assert stats.messages_dead_lettered == 4  # dead_lettered + raise + 2 unparseable
    kafka_consumer.commit.assert_awaited()
    assert producer.send.await_count >= 4


def test_kafka_disconnect_stops_clients():
    """disconnect() stops both the consumer and producer and clears them."""
    consumer = KafkaConsumer()
    kc = AsyncMock()
    prod = AsyncMock()
    consumer._consumer = kc
    consumer._producer = prod
    _run(consumer.disconnect())
    kc.stop.assert_awaited()
    prod.stop.assert_awaited()
    assert consumer._consumer is None
    assert consumer._producer is None


def test_kafka_acknowledge_is_noop():
    """Kafka acknowledgement is offset-based; acknowledge() is a no-op."""
    consumer = KafkaConsumer()
    _run(consumer.acknowledge("anything"))  # must not raise


def test_kafka_dead_letter_and_quarantine():
    """dead_letter and quarantine publish to their respective topics."""
    consumer = KafkaConsumer(
        dead_letter_topic="dlq", quarantine_topic="quarantine"
    )
    producer = AsyncMock()
    consumer._producer = producer
    msg = PipelineMessage(message_id="m1", sample_data=[1.0], source="src")

    _run(consumer.dead_letter(msg, error="failure"))
    _run(consumer.quarantine(msg, score=0.77))

    topics = [call.args[0] for call in producer.send.await_args_list]
    assert "dlq" in topics
    assert "quarantine" in topics


def test_kafka_parse_message_variants():
    """_parse_kafka_message returns a message for a valid dict and None for
    non-dict values or dicts missing sample_data."""
    good = types.SimpleNamespace(
        value={"sample_data": [1.0, 2.0], "source": "s", "k": "v"},
        topic="t", partition=1, offset=42,
    )
    parsed = KafkaConsumer._parse_kafka_message(good)
    assert parsed is not None
    assert parsed.message_id == "t:1:42"
    assert parsed.metadata == {"k": "v"}

    missing = types.SimpleNamespace(value={"nope": 1}, topic="t", partition=0, offset=0)
    assert KafkaConsumer._parse_kafka_message(missing) is None

    non_dict = types.SimpleNamespace(value="raw", topic="t", partition=0, offset=0)
    assert KafkaConsumer._parse_kafka_message(non_dict) is None


def test_pipeline_consumer_is_abstract():
    """PipelineConsumer cannot be instantiated directly (abstract methods)."""
    with pytest.raises(TypeError):
        PipelineConsumer()  # type: ignore[abstract]


def test_pipeline_stats_defaults():
    """PipelineStats defaults to a FULL, empty state."""
    stats = PipelineStats()
    assert stats.current_mode == ProcessingMode.FULL
    assert stats.messages_consumed == 0
