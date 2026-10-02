from __future__ import annotations

import asyncio
import sys
import types
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import numpy as np
import pytest
from fastapi import HTTPException

import poison_detector.api as api
from poison_detector.pipeline import (
    KafkaConsumer,
    PipelineMessage,
    ProcessingResult,
    RedisConsumer,
)


@pytest.mark.asyncio
async def test_redis_consume_routes_all_outcomes_and_malformed():
    consumer = RedisConsumer(backpressure_threshold=2, backpressure_recovery=1)
    client = SimpleNamespace(
        xreadgroup=AsyncMock(),
        xack=AsyncMock(return_value=1),
        xadd=AsyncMock(return_value="9-0"),
        xinfo_stream=AsyncMock(return_value={"length": 0}),
    )
    client.xreadgroup.return_value = [
        (
            "samples:incoming",
            [
                ("1-0", {"sample_data": "[1.0]", "source": "unit"}),
                ("2-0", {"sample_data": "[2.0]", "source": "unit"}),
                ("3-0", {"sample_data": "[3.0]", "source": "unit"}),
                ("4-0", {"sample_data": "{"}),
            ],
        )
    ]
    consumer._client = client

    async def handler(message):
        if message.message_id == "1-0":
            return ProcessingResult(message.message_id)
        if message.message_id == "2-0":
            return ProcessingResult(
                message.message_id, is_poisoned=True, score=0.91, quarantined=True
            )
        if message.message_id == "3-0":
            consumer.stop()
            return ProcessingResult(message.message_id, dead_lettered=True, error="rejected")
        raise AssertionError("unexpected")

    await consumer.consume(handler)
    assert consumer.stats.messages_consumed == 4
    assert consumer.stats.messages_processed == 2
    assert consumer.stats.messages_quarantined == 1
    assert consumer.stats.messages_dead_lettered == 2
    assert client.xack.await_count == 4
    assert client.xadd.await_count == 3


@pytest.mark.asyncio
async def test_redis_consume_empty_updates_backpressure_and_handler_exception(
    monkeypatch,
):
    consumer = RedisConsumer(backpressure_threshold=2, backpressure_recovery=1)
    client = SimpleNamespace(
        xreadgroup=AsyncMock(),
        xack=AsyncMock(return_value=1),
        xadd=AsyncMock(return_value="1-0"),
        xinfo_stream=AsyncMock(return_value={"length": 3}),
    )
    calls = {"n": 0}

    async def read_group(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return []
        return [("s", [("1-0", {"sample_data": "[1.0]"})])]

    client.xreadgroup.side_effect = read_group
    consumer._client = client

    async def handler(_message):
        consumer.stop()
        raise RuntimeError("boom")

    await consumer.consume(handler)
    assert consumer.processing_mode.value == "statistical_only"
    assert consumer.stats.messages_dead_lettered == 1
    assert client.xinfo_stream.await_count == 1


@pytest.mark.asyncio
async def test_redis_connect_busygroup_disconnect_and_real_error(monkeypatch):
    class ResponseError(Exception):
        pass

    fake_client = SimpleNamespace(
        xgroup_create=AsyncMock(
            side_effect=ResponseError("BUSYGROUP Consumer Group name already exists")
        ),
        aclose=AsyncMock(),
    )
    redis_async = types.ModuleType("redis.asyncio")
    cast(Any, redis_async).from_url = lambda *a, **k: fake_client
    redis_exc = types.ModuleType("redis.exceptions")
    cast(Any, redis_exc).ResponseError = ResponseError
    redis_pkg = types.ModuleType("redis")
    cast(Any, redis_pkg).asyncio = redis_async
    monkeypatch.setitem(sys.modules, "redis", redis_pkg)
    monkeypatch.setitem(sys.modules, "redis.asyncio", redis_async)
    monkeypatch.setitem(sys.modules, "redis.exceptions", redis_exc)

    consumer = RedisConsumer()
    await consumer.connect()
    assert consumer._running is True
    await consumer.disconnect()
    assert consumer._client is None
    fake_client.xgroup_create.side_effect = ResponseError("NOAUTH invalid password")
    with pytest.raises(ConnectionError, match="NOAUTH"):
        await consumer.connect()


@pytest.mark.asyncio
async def test_kafka_consume_routes_outcomes_commits_and_lag():
    consumer = KafkaConsumer(backpressure_threshold=2, backpressure_recovery=1)
    tp = object()
    messages = [
        SimpleNamespace(value={"sample_data": [1.0]}, topic="t", partition=0, offset=1),
        SimpleNamespace(value={"sample_data": [2.0]}, topic="t", partition=0, offset=2),
        SimpleNamespace(value={"sample_data": [3.0]}, topic="t", partition=0, offset=3),
        SimpleNamespace(value={"bad": True}, topic="t", partition=0, offset=4),
    ]
    fake = SimpleNamespace(
        getmany=AsyncMock(return_value={tp: messages}),
        commit=AsyncMock(),
        assignment=lambda: [tp],
        end_offsets=AsyncMock(return_value={tp: 10}),
        committed=AsyncMock(return_value=5),
    )
    producer = SimpleNamespace(send=AsyncMock())
    consumer._consumer = fake
    consumer._producer = producer

    async def handler(message):
        if message.message_id.endswith(":1"):
            return ProcessingResult(message.message_id)
        if message.message_id.endswith(":2"):
            return ProcessingResult(message.message_id, score=0.8, quarantined=True)
        if message.message_id.endswith(":3"):
            consumer.stop()
            return ProcessingResult(message.message_id, dead_lettered=True, error="bad")
        raise AssertionError("unexpected")

    await consumer.consume(handler)
    assert consumer.stats.messages_consumed == 4
    assert consumer.stats.messages_processed == 2
    assert consumer.stats.messages_dead_lettered == 2
    assert fake.commit.await_count == 1
    assert consumer.processing_mode.value == "statistical_only"
    assert producer.send.await_count == 3


@pytest.mark.asyncio
async def test_kafka_handler_exception_and_disconnect():
    consumer = KafkaConsumer()
    msg = SimpleNamespace(value={"sample_data": [1.0]}, topic="t", partition=0, offset=1)
    tp = object()
    fake = SimpleNamespace(
        getmany=AsyncMock(return_value={tp: [msg]}),
        commit=AsyncMock(),
        assignment=lambda: [],
        stop=AsyncMock(),
    )
    producer = SimpleNamespace(send=AsyncMock(), stop=AsyncMock())
    consumer._consumer = fake
    consumer._producer = producer

    async def handler(_message):
        consumer.stop()
        raise RuntimeError("handler")

    await consumer.consume(handler)
    assert consumer.stats.messages_dead_lettered == 1
    await consumer.disconnect()
    assert consumer._consumer is None
    assert consumer._producer is None


@pytest.mark.asyncio
async def test_kafka_connect_and_connect_failure(monkeypatch):
    created = []

    class FakeConsumer:
        def __init__(self, *args, **kwargs):
            self.start = AsyncMock()
            self.stop = AsyncMock()
            created.append(self)

    class FakeProducer:
        def __init__(self, *args, **kwargs):
            self.start = AsyncMock()
            self.stop = AsyncMock()
            self.send = AsyncMock()
            created.append(self)

    module = types.ModuleType("aiokafka")
    cast(Any, module).AIOKafkaConsumer = FakeConsumer
    cast(Any, module).AIOKafkaProducer = FakeProducer
    monkeypatch.setitem(sys.modules, "aiokafka", module)
    consumer = KafkaConsumer()
    await consumer.connect()
    assert consumer._running is True
    await consumer.disconnect()

    class BadConsumer(FakeConsumer):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.start = AsyncMock(side_effect=OSError("offline"))

    cast(Any, module).AIOKafkaConsumer = BadConsumer
    broken = KafkaConsumer()
    with pytest.raises(ConnectionError, match="offline"):
        await broken.connect()


@pytest.mark.asyncio
async def test_pipeline_methods_without_clients_are_safe():
    redis = RedisConsumer()
    with pytest.raises(RuntimeError):
        await redis.consume(AsyncMock())
    await redis.acknowledge("x")
    await redis.dead_letter(PipelineMessage("x", [1.0]), "e")
    await redis.quarantine(PipelineMessage("x", [1.0]), 1.0)
    await redis._dead_letter_raw("x", {}, "e")

    kafka = KafkaConsumer()
    with pytest.raises(RuntimeError):
        await kafka.consume(AsyncMock())
    await kafka.acknowledge("x")
    await kafka.dead_letter(PipelineMessage("x", [1.0]), "e")
    await kafka.quarantine(PipelineMessage("x", [1.0]), 1.0)


def test_rate_limiter_capacity_stale_cleanup_and_ready(monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr(api.time, "monotonic", lambda: clock["t"])
    limiter = api.RateLimiter(max_requests=2, window_seconds=10)
    assert limiter.ready() is True
    assert limiter.is_allowed("peer")
    assert limiter.is_allowed("peer")
    assert not limiter.is_allowed("peer")
    clock["t"] = 111.0
    assert limiter.is_allowed("peer")

    full = api.RateLimiter(max_requests=1, window_seconds=10)
    full._requests = {f"k{i}": [100.0] for i in range(10000)}
    clock["t"] = 200.0
    assert full.is_allowed("new")


def test_redis_rate_limiter_counts_and_health(monkeypatch):
    pipe = SimpleNamespace(
        incr=MagicMock(),
        expire=MagicMock(),
        execute=MagicMock(return_value=(1, True)),
    )
    redis_client = SimpleNamespace(
        ping=MagicMock(return_value=True),
        pipeline=MagicMock(return_value=pipe),
    )
    fake_redis = types.ModuleType("redis")
    cast(Any, fake_redis).from_url = MagicMock(return_value=redis_client)
    monkeypatch.setitem(sys.modules, "redis", fake_redis)
    limiter = api.RedisRateLimiter("redis://example", max_requests=1, window_seconds=60)
    assert limiter.is_allowed("peer") is True
    pipe.execute.return_value = (2, True)
    assert limiter.is_allowed("peer") is False
    assert limiter.ready() is True
    redis_client.ping.side_effect = OSError("down")
    assert limiter.ready() is False


@pytest.mark.asyncio
async def test_connection_manager_accept_broadcast_and_prune():
    manager = api.ConnectionManager()
    good = SimpleNamespace(accept=AsyncMock(), send_json=AsyncMock())
    bad = SimpleNamespace(accept=AsyncMock(), send_json=AsyncMock(side_effect=OSError("gone")))
    good_ws = cast(Any, good)
    bad_ws = cast(Any, bad)
    await manager.connect(good_ws)
    await manager.connect(bad_ws)
    assert manager.connection_count == 2
    await manager.broadcast({"event": "x"})
    assert manager.connection_count == 1
    manager.disconnect(good_ws)
    manager.disconnect(good_ws)
    assert manager.connection_count == 0


def test_startup_baseline_valid_and_invalid(tmp_path, monkeypatch):
    good = tmp_path / "good.npz"
    np.savez(good, features=np.ones((50, 3), dtype=np.float64))
    monkeypatch.setattr(api, "_BASELINE_PATH", str(good))
    monkeypatch.setattr(api, "_MIN_BASELINE_SAMPLES", 50)
    detector = SimpleNamespace(
        update_baseline=MagicMock(), get_stats=lambda: SimpleNamespace(baseline_size=50)
    )
    monkeypatch.setattr(api, "_detector", detector)
    api._load_startup_baseline()
    assert api._BASELINE_LOAD_ERROR is None
    detector.update_baseline.assert_called_once()

    bad = tmp_path / "bad.npz"
    np.savez(bad, wrong=np.ones((50, 3)))
    monkeypatch.setattr(api, "_BASELINE_PATH", str(bad))
    api._load_startup_baseline()
    assert api._BASELINE_LOAD_ERROR is not None
    assert "features" in api._BASELINE_LOAD_ERROR


@pytest.mark.asyncio
async def test_run_bounded_success_busy_and_failure(monkeypatch):
    slots = __import__("asyncio").Semaphore(1)
    assert await api._run_bounded(lambda x: x + 1, 1, slots, 1.0) == 2
    await slots.acquire()
    with pytest.raises(HTTPException) as busy:
        await api._run_bounded(lambda x: x, 1, slots, 1.0)
    assert busy.value.status_code == 503
    slots.release()

    def explode(_x):
        raise ValueError("bad")

    with pytest.raises(ValueError, match="bad"):
        await api._run_bounded(explode, 1, slots, 1.0)


@pytest.mark.asyncio
async def test_readiness_all_fail_closed_branches_and_ready(monkeypatch):
    monkeypatch.setattr(api, "_EXPECTED_API_KEY", "")
    assert (await api.readiness_check()).status_code == 503

    monkeypatch.setattr(api, "_EXPECTED_API_KEY", "x" * 40)
    monkeypatch.setattr(api, "_ENVIRONMENT", "production")
    monkeypatch.setattr(api, "_baseline_ready", lambda: False)
    assert (await api.readiness_check()).status_code == 503

    monkeypatch.setattr(api, "_baseline_ready", lambda: True)
    monkeypatch.setattr(api, "_rate_limiter", SimpleNamespace(ready=lambda: False))
    assert (await api.readiness_check()).status_code == 503

    monkeypatch.setattr(api, "_rate_limiter", SimpleNamespace(ready=lambda: True))
    monkeypatch.setattr(
        api,
        "_detector",
        SimpleNamespace(get_stats=MagicMock(side_effect=RuntimeError("bad"))),
    )
    assert (await api.readiness_check()).status_code == 503

    monkeypatch.setattr(
        api,
        "_detector",
        SimpleNamespace(get_stats=lambda: SimpleNamespace(baseline_size=99)),
    )
    response = await api.readiness_check()
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_score_and_batch_success_broadcast(monkeypatch):
    result = SimpleNamespace(score=0.9, is_poisoned=True, method_votes={"z": True}, latency_ms=1.2)
    monkeypatch.setattr(api, "_baseline_ready", lambda: True)
    runner = AsyncMock(side_effect=[result, [result, result]])
    monkeypatch.setattr(api, "_run_bounded", runner)
    broadcast = AsyncMock()
    monkeypatch.setattr(api._ws_manager, "broadcast", broadcast)

    single = await api.score_sample(api.SampleRequest(features=[1.0], source="unit"))
    assert single.is_poisoned is True
    batch = await api.score_batch(api.BatchRequest(samples=[[1.0], [2.0]], source="unit"))
    assert batch.poisoned_count == 2
    assert broadcast.await_count == 2


@pytest.mark.asyncio
async def test_score_and_batch_failures(monkeypatch):
    monkeypatch.setattr(api, "_baseline_ready", lambda: False)
    with pytest.raises(HTTPException) as exc:
        await api.score_sample(api.SampleRequest(features=[1.0]))
    assert exc.value.status_code == 503

    monkeypatch.setattr(api, "_baseline_ready", lambda: True)
    monkeypatch.setattr(api, "_run_bounded", AsyncMock(side_effect=asyncio.TimeoutError()))
    with pytest.raises(HTTPException) as exc:
        await api.score_sample(api.SampleRequest(features=[1.0]))
    assert exc.value.status_code == 504

    monkeypatch.setattr(api, "_run_bounded", AsyncMock(side_effect=RuntimeError("bad")))
    with pytest.raises(HTTPException) as exc:
        await api.score_batch(api.BatchRequest(samples=[[1.0]]))
    assert exc.value.status_code == 500


@pytest.mark.asyncio
async def test_health_status_transitions(monkeypatch):
    stats = SimpleNamespace(
        samples_seen=10,
        poison_rate=0.3,
        avg_latency_ms=10.0,
        baseline_size=50,
        drift_detected=False,
        window_fill=0.5,
        poison_count=3,
    )
    monkeypatch.setattr(api, "_baseline_ready", lambda: True)
    monkeypatch.setattr(api, "_detector", SimpleNamespace(get_stats=lambda: stats))
    response = await api.health_check()
    assert response.status == "degraded"
    stats.avg_latency_ms = 1001.0
    response = await api.health_check()
    assert response.status == "unhealthy"
