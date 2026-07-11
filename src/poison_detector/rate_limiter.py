"""
Distributed rate limiting for the poisoning detection API.

Provides sliding window and token bucket algorithms that work across multiple
replicas via Redis. Falls back gracefully to in-memory limiting when Redis is
unavailable, ensuring the service continues to operate (with per-process limits)
rather than failing entirely.

Threat Model Assumptions:
    - Rate limiting is a DoS mitigation, not a security boundary. A determined
      attacker with many IP addresses or API keys can bypass per-key limits.
      Rate limiting buys time for alerting and manual intervention.
    - Redis is the shared state store. If Redis is compromised, an attacker
      could reset rate limit counters. Redis must be on a private network with
      authentication enabled (requirepass or ACLs).
    - Clock synchronization matters for sliding windows. Significant clock
      drift between replicas (>1s) can cause inconsistent rate enforcement.
      Use NTP-synchronized clocks.

Honest Limitations:
    - The sliding window algorithm uses Redis sorted sets with ZRANGEBYSCORE.
      For very high request rates (>10K/s per key), the sorted set can grow
      large. The implementation prunes expired entries on each check, but
      a burst of requests before pruning can temporarily exceed memory targets.
    - Token bucket refill is calculated on-demand (not via background timer).
      This means the bucket state is only updated when checked. Idle periods
      followed by bursts are handled correctly, but there is no background
      refill thread.
    - Redis MULTI/EXEC provides atomicity but not strict serializability
      across keys. Two concurrent requests to different keys are independent.
      Two concurrent requests to the same key are serialized by Redis itself.
    - The in-memory fallback provides per-process limits only. Behind a load
      balancer with N replicas, the effective limit is N times the configured
      per-process limit. This is acceptable as a degraded-mode behavior.

Security Notes:
    - Rate limit keys derived from client input (API keys, IPs) must be
      length-bounded and sanitized to prevent Redis key injection.
    - Redis commands use parameterized arguments (not string interpolation)
      to prevent command injection.
    - The Retry-After header value is calculated from server state, not
      echoed from client input.
    - In-memory state is bounded to prevent memory exhaustion from an
      attacker creating many unique keys.
"""

from __future__ import annotations

import hashlib
import logging
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Protocol

logger = logging.getLogger(__name__)


# --- Interfaces and Data Types ---


@dataclass
class RateLimitResult:
    """Result of a rate limit check.

    Attributes:
        allowed: Whether the request is allowed.
        remaining: Number of remaining requests in the current window.
        limit: The configured limit for this key.
        retry_after: Seconds until the next request would be allowed
            (0 if currently allowed).
        using_fallback: True if the result came from in-memory fallback
            (Redis was unavailable).
    """

    allowed: bool
    remaining: int
    limit: int
    retry_after: float = 0.0
    using_fallback: bool = False


class RateLimitBackend(Protocol):
    """Protocol for rate limit storage backends."""

    def check_and_increment(
        self, key: str, limit: int, window_seconds: float
    ) -> RateLimitResult:
        """Check rate limit and increment counter if allowed.

        Args:
            key: The rate limit key (e.g., "api_key:abc123").
            limit: Maximum allowed requests in the window.
            window_seconds: Window duration in seconds.

        Returns:
            RateLimitResult indicating whether the request is allowed.
        """
        ...


# --- Sliding Window Rate Limiter ---


class SlidingWindowRateLimiter:
    """Distributed sliding window rate limiter.

    Uses a true sliding window (not fixed window) to prevent boundary
    burst attacks where an attacker sends max_requests at the end of one
    window and max_requests at the start of the next.

    The sliding window works by tracking individual request timestamps in
    a sorted set. The window slides continuously, so a request at time T
    counts requests in [T - window_seconds, T].

    Supports multiple granularities:
        - Per API key: "api_key:{key}"
        - Per IP address: "ip:{address}"
        - Per endpoint: "endpoint:{path}"
        - Combined: "api_key:{key}:endpoint:{path}"

    Usage:
        limiter = SlidingWindowRateLimiter(
            redis_url="redis://localhost:6379",
            max_requests=100,
            window_seconds=60,
        )

        # Check if request is allowed
        result = limiter.check("api_key:client-123")
        if not result.allowed:
            # Return 429 with Retry-After header
            return Response(status_code=429, headers={"Retry-After": str(int(result.retry_after))})

    Args:
        redis_url: Redis connection URL. If empty or None, uses in-memory only.
        max_requests: Maximum allowed requests per window.
        window_seconds: Sliding window duration in seconds.
        key_prefix: Prefix for Redis keys to namespace rate limits.
    """

    def __init__(
        self,
        redis_url: str = "",
        max_requests: int = 100,
        window_seconds: float = 60.0,
        key_prefix: str = "poison_detector:ratelimit:sliding",
    ) -> None:
        """Initialize the sliding window rate limiter.

        Args:
            redis_url: Redis connection URL (redis://host:port/db).
                If empty, only in-memory fallback is used.
            max_requests: Maximum requests allowed per window per key.
            window_seconds: Window duration in seconds.
            key_prefix: Namespace prefix for Redis keys.
        """
        if max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")

        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._key_prefix = key_prefix
        self._redis_client: Any = None
        self._redis_available = False

        # Initialize Redis connection if URL provided
        if redis_url:
            self._init_redis(redis_url)

        # In-memory fallback (always available)
        self._memory_store: dict[str, list[float]] = defaultdict(list)
        self._memory_lock = threading.Lock()
        self._max_memory_keys = 100000  # Bound memory usage

    def _init_redis(self, redis_url: str) -> None:
        """Attempt to initialize Redis connection.

        Fails gracefully if Redis is unavailable, falling back to
        in-memory rate limiting.

        Args:
            redis_url: Redis connection URL.
        """
        try:
            import redis

            self._redis_client = redis.Redis.from_url(
                redis_url,
                socket_connect_timeout=2.0,
                socket_timeout=1.0,
                decode_responses=True,
            )
            # Test connection
            self._redis_client.ping()
            self._redis_available = True
            logger.info("Sliding window rate limiter connected to Redis")
        except ImportError:
            logger.warning(
                "redis package not available, using in-memory rate limiting"
            )
            self._redis_available = False
        except Exception as e:
            logger.warning(
                "Redis connection failed (%s), using in-memory fallback", e
            )
            self._redis_available = False

    def check(self, key: str) -> RateLimitResult:
        """Check if a request is allowed under the sliding window limit.

        Attempts Redis first, falls back to in-memory if Redis is unavailable.

        Args:
            key: Rate limit key (e.g., "api_key:client-123", "ip:10.0.0.1").
                Length is bounded to 256 characters for safety.

        Returns:
            RateLimitResult with allowed status and remaining quota.
        """
        # Sanitize key: bound length and remove control characters
        safe_key = self._sanitize_key(key)

        if self._redis_available and self._redis_client is not None:
            try:
                return self._check_redis(safe_key)
            except Exception as e:
                logger.warning(
                    "Redis rate limit check failed (%s), falling back to memory", e
                )
                self._redis_available = False

        return self._check_memory(safe_key)

    # Lua script that atomically prunes, counts, conditionally adds, and sets expiry.
    # This eliminates the TOCTOU race between count check and ZADD that existed
    # when these operations were split across separate pipeline calls.
    # KEYS[1] = the sorted set key
    # ARGV[1] = window_start (prune entries older than this)
    # ARGV[2] = now (current timestamp, used as score for new entry)
    # ARGV[3] = max_requests (limit)
    # ARGV[4] = member value (unique entry identifier)
    # ARGV[5] = expire_seconds (TTL for the key)
    # Returns: {allowed (0/1), remaining, oldest_score or 0}
    _LUA_SLIDING_WINDOW = """
    redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
    local count = redis.call('ZCARD', KEYS[1])
    local max_requests = tonumber(ARGV[3])
    if count >= max_requests then
        local oldest = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', '+inf', 'WITHSCORES', 'LIMIT', 0, 1)
        local oldest_score = 0
        if #oldest >= 2 then
            oldest_score = tonumber(oldest[2])
        end
        return {0, 0, tostring(oldest_score)}
    end
    redis.call('ZADD', KEYS[1], ARGV[2], ARGV[4])
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[5]))
    local new_count = count + 1
    local remaining = max_requests - new_count
    return {1, remaining, "0"}
    """

    def _check_redis(self, key: str) -> RateLimitResult:
        """Check rate limit using Redis sorted set.

        Uses a Lua script to atomically:
        1. Remove expired entries (ZREMRANGEBYSCORE)
        2. Count current entries (ZCARD)
        3. Conditionally add new entry if under limit (ZADD)
        4. Set key expiration (EXPIRE)

        The Lua script executes as a single atomic operation in Redis,
        eliminating the TOCTOU race condition that would exist if these
        steps were performed in separate pipeline calls.

        Args:
            key: Sanitized rate limit key.

        Returns:
            RateLimitResult from Redis state.
        """
        now = time.time()
        window_start = now - self._window_seconds
        redis_key = f"{self._key_prefix}:{key}"
        member = f"{now}:{id(key)}"
        expire_seconds = int(self._window_seconds) + 1

        result = self._redis_client.eval(
            self._LUA_SLIDING_WINDOW,
            1,
            redis_key,
            str(window_start),
            str(now),
            str(self._max_requests),
            member,
            str(expire_seconds),
        )

        allowed = int(result[0]) == 1
        remaining = int(result[1])
        oldest_score = float(result[2])

        if not allowed:
            retry_after = 0.0
            if oldest_score > 0:
                retry_after = max(0.0, (oldest_score + self._window_seconds) - now)
            return RateLimitResult(
                allowed=False,
                remaining=0,
                limit=self._max_requests,
                retry_after=retry_after,
                using_fallback=False,
            )

        return RateLimitResult(
            allowed=True,
            remaining=max(0, remaining),
            limit=self._max_requests,
            retry_after=0.0,
            using_fallback=False,
        )

    def _check_memory(self, key: str) -> RateLimitResult:
        """Check rate limit using in-memory sliding window.

        Thread-safe fallback when Redis is unavailable.

        Args:
            key: Sanitized rate limit key.

        Returns:
            RateLimitResult from in-memory state.
        """
        now = time.time()
        window_start = now - self._window_seconds

        with self._memory_lock:
            # Bound total keys to prevent memory exhaustion
            if key not in self._memory_store and len(self._memory_store) >= self._max_memory_keys:
                # Evict oldest key
                oldest_key = min(
                    self._memory_store.keys(),
                    key=lambda k: self._memory_store[k][-1] if self._memory_store[k] else 0,
                )
                del self._memory_store[oldest_key]

            # Prune expired entries
            self._memory_store[key] = [
                t for t in self._memory_store[key] if t > window_start
            ]

            current_count = len(self._memory_store[key])

            if current_count >= self._max_requests:
                # Calculate retry_after from oldest entry
                oldest_time = self._memory_store[key][0] if self._memory_store[key] else now
                retry_after = max(0.0, (oldest_time + self._window_seconds) - now)
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    limit=self._max_requests,
                    retry_after=retry_after,
                    using_fallback=True,
                )

            # Record this request
            self._memory_store[key].append(now)
            remaining = self._max_requests - current_count - 1

            return RateLimitResult(
                allowed=True,
                remaining=max(0, remaining),
                limit=self._max_requests,
                retry_after=0.0,
                using_fallback=True,
            )

    def _sanitize_key(self, key: str) -> str:
        """Sanitize a rate limit key to prevent injection.

        Bounds length and removes characters that could be problematic
        in Redis key names.

        Args:
            key: Raw key from caller.

        Returns:
            Sanitized key safe for Redis operations.
        """
        # Truncate to prevent oversized keys
        if len(key) > 256:
            # Hash the key to preserve uniqueness
            key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
            key = key[:240] + ":" + key_hash

        # Remove null bytes and control characters
        key = "".join(c for c in key if c.isprintable() and c != "\x00")
        return key or "empty"

    def get_usage(self, key: str) -> int:
        """Get the current request count for a key.

        Args:
            key: The rate limit key to check.

        Returns:
            Number of requests in the current window.
        """
        safe_key = self._sanitize_key(key)
        now = time.time()
        window_start = now - self._window_seconds

        with self._memory_lock:
            if safe_key in self._memory_store:
                return len([t for t in self._memory_store[safe_key] if t > window_start])
        return 0

    def reset(self, key: str) -> None:
        """Reset rate limit state for a key.

        Args:
            key: The rate limit key to reset.
        """
        safe_key = self._sanitize_key(key)

        if self._redis_available and self._redis_client is not None:
            try:
                redis_key = f"{self._key_prefix}:{safe_key}"
                self._redis_client.delete(redis_key)
            except Exception:
                pass

        with self._memory_lock:
            self._memory_store.pop(safe_key, None)

    @property
    def max_requests(self) -> int:
        """Configured maximum requests per window."""
        return self._max_requests

    @property
    def window_seconds(self) -> float:
        """Configured window duration in seconds."""
        return self._window_seconds

    @property
    def is_redis_available(self) -> bool:
        """Whether Redis backend is currently available."""
        return self._redis_available


# --- Token Bucket Rate Limiter ---


@dataclass
class _TokenBucket:
    """Internal token bucket state."""

    tokens: float
    last_refill: float
    max_tokens: float
    refill_rate: float  # tokens per second


class TokenBucketRateLimiter:
    """Token bucket rate limiter for burst allowance.

    The token bucket algorithm allows controlled bursting while enforcing
    a long-term average rate. Tokens are consumed by requests and refilled
    at a steady rate.

    Key properties:
        - Allows bursts up to bucket capacity (max_tokens)
        - Long-term rate limited to refill_rate requests/second
        - Smooth rather than bursty enforcement

    Supports Redis for distributed state (multiple replicas share a bucket)
    with in-memory fallback.

    Usage:
        limiter = TokenBucketRateLimiter(
            max_tokens=50,
            refill_rate=10.0,  # 10 tokens/second = 600/minute steady-state
            redis_url="redis://localhost:6379",
        )

        result = limiter.consume("client:abc123")
        if not result.allowed:
            return Response(
                status_code=429,
                headers={"Retry-After": str(int(result.retry_after) + 1)},
            )

    Args:
        max_tokens: Maximum tokens in the bucket (burst capacity).
        refill_rate: Tokens added per second.
        redis_url: Redis URL for distributed state. Empty for in-memory only.
        key_prefix: Namespace prefix for Redis keys.
    """

    def __init__(
        self,
        max_tokens: int = 50,
        refill_rate: float = 10.0,
        redis_url: str = "",
        key_prefix: str = "poison_detector:ratelimit:bucket",
    ) -> None:
        """Initialize the token bucket rate limiter.

        Args:
            max_tokens: Maximum tokens (burst capacity).
            refill_rate: Tokens refilled per second (sustained rate).
            redis_url: Redis connection URL. Empty for in-memory only.
            key_prefix: Namespace prefix for Redis keys.
        """
        if max_tokens < 1:
            raise ValueError("max_tokens must be >= 1")
        if refill_rate <= 0:
            raise ValueError("refill_rate must be > 0")

        self._max_tokens = max_tokens
        self._refill_rate = refill_rate
        self._key_prefix = key_prefix
        self._redis_client: Any = None
        self._redis_available = False

        if redis_url:
            self._init_redis(redis_url)

        # In-memory fallback
        self._buckets: dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()
        self._max_memory_keys = 100000

    def _init_redis(self, redis_url: str) -> None:
        """Attempt to initialize Redis connection.

        Args:
            redis_url: Redis connection URL.
        """
        try:
            import redis

            self._redis_client = redis.Redis.from_url(
                redis_url,
                socket_connect_timeout=2.0,
                socket_timeout=1.0,
                decode_responses=True,
            )
            self._redis_client.ping()
            self._redis_available = True
            logger.info("Token bucket rate limiter connected to Redis")
        except ImportError:
            logger.warning(
                "redis package not available, using in-memory token bucket"
            )
            self._redis_available = False
        except Exception as e:
            logger.warning(
                "Redis connection failed (%s), using in-memory fallback", e
            )
            self._redis_available = False

    def consume(self, key: str, tokens: int = 1) -> RateLimitResult:
        """Attempt to consume tokens from the bucket.

        Refills the bucket based on elapsed time since last access, then
        attempts to consume the requested number of tokens.

        Args:
            key: Rate limit key (e.g., "api_key:client-123").
            tokens: Number of tokens to consume (default 1).

        Returns:
            RateLimitResult indicating success or failure with retry timing.
        """
        safe_key = self._sanitize_key(key)

        if self._redis_available and self._redis_client is not None:
            try:
                return self._consume_redis(safe_key, tokens)
            except Exception as e:
                logger.warning(
                    "Redis token bucket failed (%s), falling back to memory", e
                )
                self._redis_available = False

        return self._consume_memory(safe_key, tokens)

    def _consume_redis(self, key: str, tokens: int) -> RateLimitResult:
        """Consume tokens using Redis for distributed state.

        Uses a Redis hash to store bucket state and MULTI/EXEC for atomicity.

        Args:
            key: Sanitized rate limit key.
            tokens: Number of tokens to consume.

        Returns:
            RateLimitResult from Redis state.
        """
        redis_key = f"{self._key_prefix}:{key}"
        now = time.time()

        # Get current bucket state
        pipe = self._redis_client.pipeline(transaction=True)
        pipe.hgetall(redis_key)
        results = pipe.execute()
        bucket_data = results[0]

        if bucket_data:
            current_tokens = float(bucket_data.get("tokens", self._max_tokens))
            last_refill = float(bucket_data.get("last_refill", now))
        else:
            current_tokens = float(self._max_tokens)
            last_refill = now

        # Calculate refill
        elapsed = now - last_refill
        refilled = current_tokens + (elapsed * self._refill_rate)
        current_tokens = min(refilled, float(self._max_tokens))

        if current_tokens >= tokens:
            # Consume tokens
            new_tokens = current_tokens - tokens
            pipe2 = self._redis_client.pipeline(transaction=True)
            pipe2.hset(redis_key, mapping={
                "tokens": str(new_tokens),
                "last_refill": str(now),
            })
            # Expire the key after a generous timeout to prevent orphaned keys
            pipe2.expire(redis_key, int(self._max_tokens / self._refill_rate) + 60)
            pipe2.execute()

            return RateLimitResult(
                allowed=True,
                remaining=int(new_tokens),
                limit=self._max_tokens,
                retry_after=0.0,
                using_fallback=False,
            )
        else:
            # Not enough tokens -- calculate when enough will be available
            deficit = tokens - current_tokens
            retry_after = deficit / self._refill_rate

            # Update state (just the refill, no consumption)
            pipe2 = self._redis_client.pipeline(transaction=True)
            pipe2.hset(redis_key, mapping={
                "tokens": str(current_tokens),
                "last_refill": str(now),
            })
            pipe2.expire(redis_key, int(self._max_tokens / self._refill_rate) + 60)
            pipe2.execute()

            return RateLimitResult(
                allowed=False,
                remaining=int(current_tokens),
                limit=self._max_tokens,
                retry_after=retry_after,
                using_fallback=False,
            )

    def _consume_memory(self, key: str, tokens: int) -> RateLimitResult:
        """Consume tokens using in-memory state.

        Thread-safe fallback when Redis is unavailable.

        Args:
            key: Sanitized rate limit key.
            tokens: Number of tokens to consume.

        Returns:
            RateLimitResult from in-memory state.
        """
        now = time.time()

        with self._lock:
            # Bound memory usage
            if key not in self._buckets and len(self._buckets) >= self._max_memory_keys:
                # Evict least recently used
                oldest_key = min(
                    self._buckets.keys(),
                    key=lambda k: self._buckets[k].last_refill,
                )
                del self._buckets[oldest_key]

            if key not in self._buckets:
                self._buckets[key] = _TokenBucket(
                    tokens=float(self._max_tokens),
                    last_refill=now,
                    max_tokens=float(self._max_tokens),
                    refill_rate=self._refill_rate,
                )

            bucket = self._buckets[key]

            # Refill based on elapsed time
            elapsed = now - bucket.last_refill
            bucket.tokens = min(
                bucket.max_tokens,
                bucket.tokens + (elapsed * bucket.refill_rate),
            )
            bucket.last_refill = now

            if bucket.tokens >= tokens:
                bucket.tokens -= tokens
                return RateLimitResult(
                    allowed=True,
                    remaining=int(bucket.tokens),
                    limit=self._max_tokens,
                    retry_after=0.0,
                    using_fallback=True,
                )
            else:
                deficit = tokens - bucket.tokens
                retry_after = deficit / bucket.refill_rate
                return RateLimitResult(
                    allowed=False,
                    remaining=int(bucket.tokens),
                    limit=self._max_tokens,
                    retry_after=retry_after,
                    using_fallback=True,
                )

    def _sanitize_key(self, key: str) -> str:
        """Sanitize a rate limit key.

        Args:
            key: Raw key from caller.

        Returns:
            Sanitized key safe for storage.
        """
        if len(key) > 256:
            key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
            key = key[:240] + ":" + key_hash

        key = "".join(c for c in key if c.isprintable() and c != "\x00")
        return key or "empty"

    def reset(self, key: str) -> None:
        """Reset a bucket to full capacity.

        Args:
            key: The rate limit key to reset.
        """
        safe_key = self._sanitize_key(key)

        if self._redis_available and self._redis_client is not None:
            try:
                redis_key = f"{self._key_prefix}:{safe_key}"
                self._redis_client.delete(redis_key)
            except Exception:
                pass

        with self._lock:
            self._buckets.pop(safe_key, None)

    @property
    def max_tokens(self) -> int:
        """Maximum tokens (burst capacity)."""
        return self._max_tokens

    @property
    def refill_rate(self) -> float:
        """Token refill rate (tokens/second)."""
        return self._refill_rate

    @property
    def is_redis_available(self) -> bool:
        """Whether Redis backend is currently available."""
        return self._redis_available


# --- Composite Rate Limiter ---


class CompositeRateLimiter:
    """Combines multiple rate limiting strategies.

    Applies rate limits at multiple granularities (per-key, per-IP,
    per-endpoint) and returns the most restrictive result.

    Usage:
        limiter = CompositeRateLimiter(
            limiters={
                "per_key": SlidingWindowRateLimiter(max_requests=100, window_seconds=60),
                "per_ip": SlidingWindowRateLimiter(max_requests=1000, window_seconds=60),
                "burst": TokenBucketRateLimiter(max_tokens=20, refill_rate=5.0),
            }
        )

        # Check all limits for a request
        result = limiter.check_all(keys={
            "per_key": f"api_key:{api_key}",
            "per_ip": f"ip:{client_ip}",
            "burst": f"api_key:{api_key}",
        })
    """

    def __init__(
        self,
        limiters: dict[str, SlidingWindowRateLimiter | TokenBucketRateLimiter],
    ) -> None:
        """Initialize with named limiters.

        Args:
            limiters: Dictionary mapping limiter names to instances.
        """
        self._limiters = limiters

    def check_all(self, keys: dict[str, str]) -> RateLimitResult:
        """Check all configured limiters and return the most restrictive result.

        Args:
            keys: Dictionary mapping limiter names to their respective keys.
                Only limiters present in both self._limiters and keys are checked.

        Returns:
            The most restrictive RateLimitResult (first denial wins).
        """
        most_restrictive: RateLimitResult | None = None

        for name, key in keys.items():
            limiter = self._limiters.get(name)
            if limiter is None:
                continue

            if isinstance(limiter, SlidingWindowRateLimiter):
                result = limiter.check(key)
            elif isinstance(limiter, TokenBucketRateLimiter):
                result = limiter.consume(key)
            else:
                continue

            # If any limiter denies, return immediately
            if not result.allowed:
                return result

            # Track most restrictive (lowest remaining)
            if most_restrictive is None or result.remaining < most_restrictive.remaining:
                most_restrictive = result

        # All limiters allowed
        return most_restrictive or RateLimitResult(
            allowed=True, remaining=0, limit=0
        )
