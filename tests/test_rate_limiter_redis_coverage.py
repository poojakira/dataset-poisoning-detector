"""Coverage tests for the Redis-backed rate limiter paths.

Redis is not reachable in this environment, so these tests inject a scripted
fake Redis client to drive `_check_redis` / `_consume_redis`, the reset-via-Redis
branch, the Redis-error -> in-memory fallback, and `_init_redis` connection
handling. No real Redis server is contacted.
"""

import sys
import time
from unittest.mock import MagicMock, patch

from poison_detector.rate_limiter import (
    SlidingWindowRateLimiter,
    TokenBucketRateLimiter,
)


class _FakePipe:
    """Minimal Redis pipeline stand-in backed by an in-memory dict."""

    def __init__(self, store):
        self._store = store
        self._queued = []

    def hgetall(self, key):
        self._queued.append(("hgetall", key))
        return self

    def hset(self, key, mapping=None):
        self._store[key] = dict(mapping or {})
        self._queued.append(("hset", key))
        return self

    def expire(self, key, ttl):
        self._queued.append(("expire", key))
        return self

    def execute(self):
        results = []
        for op, key in self._queued:
            results.append(self._store.get(key, {}) if op == "hgetall" else True)
        self._queued = []
        return results


class _ScriptedRedis:
    """Fake Redis client: eval() returns scripted results, hashes via _FakePipe."""

    def __init__(self, eval_results=None, raise_on_eval=False):
        self._eval_results = list(eval_results or [])
        self._raise_on_eval = raise_on_eval
        self.store = {}
        self.deleted = []

    def ping(self):
        return True

    def eval(self, *args):
        if self._raise_on_eval:
            raise RuntimeError("redis down")
        return self._eval_results.pop(0)

    def delete(self, key):
        self.deleted.append(key)

    def pipeline(self, transaction=True):
        return _FakePipe(self.store)


# --------------------------------------------------------------------------
# Sliding window Redis path
# --------------------------------------------------------------------------


def test_sliding_window_redis_allow_then_block():
    """_check_redis maps the Lua result to allow/deny with retry_after."""
    limiter = SlidingWindowRateLimiter(redis_url="", max_requests=5, window_seconds=60.0)
    limiter._redis_client = _ScriptedRedis(
        eval_results=[[1, 4, "0"], [0, 0, str(time.time())]]
    )
    limiter._redis_available = True

    allowed = limiter.check("api_key:abc")
    assert allowed.allowed is True
    assert allowed.using_fallback is False
    assert allowed.remaining == 4

    blocked = limiter.check("api_key:abc")
    assert blocked.allowed is False
    assert blocked.using_fallback is False
    assert blocked.retry_after >= 0.0


def test_sliding_window_redis_reset_deletes_key():
    """reset() issues a Redis DELETE when the backend is available."""
    limiter = SlidingWindowRateLimiter(redis_url="", max_requests=5, window_seconds=60.0)
    fake = _ScriptedRedis()
    limiter._redis_client = fake
    limiter._redis_available = True
    limiter.reset("api_key:abc")
    assert any("api_key:abc" in k for k in fake.deleted)


def test_sliding_window_redis_error_falls_back_to_memory():
    """A Redis error during check disables Redis and uses the in-memory path."""
    limiter = SlidingWindowRateLimiter(redis_url="", max_requests=2, window_seconds=60.0)
    limiter._redis_client = _ScriptedRedis(raise_on_eval=True)
    limiter._redis_available = True

    result = limiter.check("k")
    assert result.allowed is True
    assert result.using_fallback is True  # switched to memory
    assert limiter.is_redis_available is False


# --------------------------------------------------------------------------
# Token bucket Redis path
# --------------------------------------------------------------------------


def test_token_bucket_redis_allow_then_deny():
    """_consume_redis serves from a full bucket, then denies once drained."""
    limiter = TokenBucketRateLimiter(max_tokens=5, refill_rate=0.001, redis_url="")
    limiter._redis_client = _ScriptedRedis()
    limiter._redis_available = True

    first = limiter.consume("api_key:abc", tokens=5)
    assert first.allowed is True
    assert first.using_fallback is False

    # Bucket is now ~empty and refill is negligible -> deny
    second = limiter.consume("api_key:abc", tokens=5)
    assert second.allowed is False
    assert second.retry_after > 0
    assert second.using_fallback is False


def test_token_bucket_redis_reset_deletes_key():
    """reset() issues a Redis DELETE for the bucket key."""
    limiter = TokenBucketRateLimiter(max_tokens=5, refill_rate=1.0, redis_url="")
    fake = _ScriptedRedis()
    limiter._redis_client = fake
    limiter._redis_available = True
    limiter.reset("api_key:abc")
    assert any("api_key:abc" in k for k in fake.deleted)


def test_token_bucket_redis_error_falls_back_to_memory():
    """A Redis failure during consume disables Redis and uses memory."""
    limiter = TokenBucketRateLimiter(max_tokens=2, refill_rate=1.0, redis_url="")

    class _BoomRedis(_ScriptedRedis):
        def pipeline(self, transaction=True):
            raise RuntimeError("redis down")

    limiter._redis_client = _BoomRedis()
    limiter._redis_available = True

    result = limiter.consume("k")
    assert result.allowed is True
    assert result.using_fallback is True
    assert limiter.is_redis_available is False


# --------------------------------------------------------------------------
# _init_redis connection handling
# --------------------------------------------------------------------------


def test_init_redis_success():
    """A reachable Redis (mocked ping) marks the backend available."""
    fake = _ScriptedRedis()
    with patch("redis.Redis.from_url", MagicMock(return_value=fake)):
        limiter = SlidingWindowRateLimiter(
            redis_url="redis://localhost:6379", max_requests=5, window_seconds=60.0
        )
    assert limiter.is_redis_available is True


def test_init_redis_import_error_uses_memory():
    """When the redis package is unavailable, the limiter uses in-memory only."""
    with patch.dict(sys.modules, {"redis": None}):
        limiter = TokenBucketRateLimiter(
            max_tokens=5, refill_rate=1.0, redis_url="redis://localhost:6379"
        )
    assert limiter.is_redis_available is False
    # Still functional via memory
    assert limiter.consume("k").allowed is True
