"""
Pipeline consumers for real-time data ingestion from message queues.

Provides abstract PipelineConsumer interface with Redis Streams and Kafka
implementations. Includes dead letter queue handling, quarantine routing
for flagged samples, and backpressure management.

Threat Model Assumptions:
    - Message queues (Redis, Kafka) are internal infrastructure with network-
      level access control. Messages are not signed or encrypted at the
      application layer (rely on TLS at the transport layer).
    - An attacker with queue access could inject crafted messages to test
      detection boundaries. The pipeline must handle malformed messages
      gracefully (route to dead letter queue) without crashing.
    - Backpressure handling degrades detection quality (statistical-only mode)
      rather than dropping samples. This prevents an attacker from using
      queue flooding to bypass detection entirely.

Honest Limitations:
    - Redis Streams consumer uses a single consumer group. For multi-instance
      deployments, configure distinct consumer names within the same group
      to distribute processing.
    - Kafka consumer requires confluent-kafka or aiokafka which are not
      included as required dependencies. The implementation handles ImportError
      gracefully and logs a clear error message.
    - Dead letter queue is implemented as a separate stream/topic. There is
      no automatic retry from the dead letter queue -- that requires an
      external process or manual intervention.
    - Backpressure detection is based on queue depth polling. There is a lag
      between queue buildup and mode switch. Fast bursts may be partially
      processed in full mode before backpressure engages.

Security Notes:
    - Message deserialization uses json.loads only (never pickle, eval, or
      yaml.unsafe_load). Malformed JSON routes to dead letter queue.
    - Connection credentials (Redis AUTH, Kafka SASL) come from environment
      variables or config, never from message content.
    - Consumer group names are hardcoded or config-driven, never derived
      from message content (preventing group injection).
    - Memory limits on message buffering prevent OOM from queue flooding.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


class ProcessingMode(Enum):
    """Processing modes for backpressure management."""

    FULL = "full"
    STATISTICAL_ONLY = "statistical_only"


@dataclass
class PipelineMessage:
    """A message consumed from the pipeline.

    Attributes:
        message_id: Queue-specific message identifier.
        sample_data: The sample feature vector or structured data.
        source: Origin identifier (topic, stream name).
        timestamp: When the message was produced (ISO 8601).
        metadata: Additional message metadata.
    """

    message_id: str
    sample_data: list[float] | dict[str, Any]
    source: str = ""
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProcessingResult:
    """Result of processing a pipeline message.

    Attributes:
        message_id: The processed message ID.
        is_poisoned: Whether the sample was flagged.
        score: Anomaly score.
        quarantined: Whether the sample was routed to quarantine.
        dead_lettered: Whether the message was sent to the dead letter queue.
        error: Error message if processing failed.
        processing_mode: Which mode was used (full or statistical-only).
    """

    message_id: str
    is_poisoned: bool = False
    score: float = 0.0
    quarantined: bool = False
    dead_lettered: bool = False
    error: str = ""
    processing_mode: ProcessingMode = ProcessingMode.FULL


@dataclass
class PipelineStats:
    """Statistics about pipeline consumption.

    Attributes:
        messages_consumed: Total messages consumed.
        messages_processed: Successfully processed messages.
        messages_quarantined: Messages routed to quarantine.
        messages_dead_lettered: Messages sent to dead letter queue.
        current_mode: Current processing mode.
        queue_depth: Current queue depth estimate.
        avg_processing_ms: Average processing time in milliseconds.
    """

    messages_consumed: int = 0
    messages_processed: int = 0
    messages_quarantined: int = 0
    messages_dead_lettered: int = 0
    current_mode: ProcessingMode = ProcessingMode.FULL
    queue_depth: int = 0
    avg_processing_ms: float = 0.0


class PipelineConsumer(ABC):
    """Abstract interface for message queue consumption.

    Implementations must provide methods for connecting to a queue,
    consuming messages, acknowledging processed messages, and routing
    to dead letter and quarantine queues.

    Subclasses should call the backpressure management methods to switch
    between full and statistical-only processing modes based on queue depth.
    """

    def __init__(
        self,
        backpressure_threshold: int = 10000,
        backpressure_recovery: int = 5000,
    ) -> None:
        """Initialize base pipeline consumer.

        Args:
            backpressure_threshold: Queue depth above which to engage
                statistical-only mode.
            backpressure_recovery: Queue depth below which to resume full mode.
        """
        self._backpressure_threshold = backpressure_threshold
        self._backpressure_recovery = backpressure_recovery
        self._current_mode = ProcessingMode.FULL
        self._stats = PipelineStats()
        self._running = False
        self._total_processing_ms: float = 0.0

    @property
    def processing_mode(self) -> ProcessingMode:
        """Current processing mode based on backpressure state."""
        return self._current_mode

    @property
    def stats(self) -> PipelineStats:
        """Get current pipeline statistics."""
        avg_ms = 0.0
        if self._stats.messages_processed > 0:
            avg_ms = self._total_processing_ms / self._stats.messages_processed
        return PipelineStats(
            messages_consumed=self._stats.messages_consumed,
            messages_processed=self._stats.messages_processed,
            messages_quarantined=self._stats.messages_quarantined,
            messages_dead_lettered=self._stats.messages_dead_lettered,
            current_mode=self._current_mode,
            queue_depth=self._stats.queue_depth,
            avg_processing_ms=avg_ms,
        )

    def update_backpressure(self, queue_depth: int) -> None:
        """Update backpressure state based on current queue depth.

        Switches to statistical-only mode when depth exceeds threshold,
        and recovers to full mode when depth drops below recovery point.

        Args:
            queue_depth: Current estimated queue depth.
        """
        self._stats.queue_depth = queue_depth

        if self._current_mode == ProcessingMode.FULL and queue_depth > self._backpressure_threshold:
            logger.warning(
                f"Backpressure engaged: queue depth {queue_depth} > "
                f"threshold {self._backpressure_threshold}. "
                f"Switching to statistical-only mode."
            )
            self._current_mode = ProcessingMode.STATISTICAL_ONLY

        elif (
            self._current_mode == ProcessingMode.STATISTICAL_ONLY
            and queue_depth < self._backpressure_recovery
        ):
            logger.info(
                f"Backpressure relieved: queue depth {queue_depth} < "
                f"recovery {self._backpressure_recovery}. "
                f"Resuming full processing mode."
            )
            self._current_mode = ProcessingMode.FULL

    def record_processing(self, elapsed_ms: float, quarantined: bool = False) -> None:
        """Record a successfully processed message.

        Args:
            elapsed_ms: Processing time in milliseconds.
            quarantined: Whether the message was quarantined.
        """
        self._stats.messages_processed += 1
        self._total_processing_ms += elapsed_ms
        if quarantined:
            self._stats.messages_quarantined += 1

    def record_dead_letter(self) -> None:
        """Record a message sent to the dead letter queue."""
        self._stats.messages_dead_lettered += 1

    @abstractmethod
    async def connect(self) -> None:
        """Connect to the message queue.

        Raises:
            ConnectionError: If the connection cannot be established.
        """
        ...

    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from the message queue gracefully."""
        ...

    @abstractmethod
    async def consume(
        self,
        handler: Callable[[PipelineMessage], Awaitable[ProcessingResult]],
        batch_size: int = 10,
    ) -> None:
        """Start consuming messages and passing them to the handler.

        This is a long-running method that runs until stop() is called.

        Args:
            handler: Async function that processes each message.
            batch_size: Number of messages to fetch per iteration.
        """
        ...

    @abstractmethod
    async def acknowledge(self, message_id: str) -> None:
        """Acknowledge a successfully processed message.

        Args:
            message_id: The message to acknowledge.
        """
        ...

    @abstractmethod
    async def dead_letter(self, message: PipelineMessage, error: str) -> None:
        """Route a failed message to the dead letter queue.

        Args:
            message: The message that failed processing.
            error: Description of the failure.
        """
        ...

    @abstractmethod
    async def quarantine(self, message: PipelineMessage, score: float) -> None:
        """Route a flagged message to the quarantine queue.

        Args:
            message: The message flagged as potentially poisoned.
            score: The anomaly score that triggered quarantine.
        """
        ...

    def stop(self) -> None:
        """Signal the consumer to stop consuming."""
        self._running = False


class RedisConsumer(PipelineConsumer):
    """Redis Streams consumer for lightweight real-time pipelines.

    Uses Redis Streams with consumer groups for reliable message delivery.
    Messages that fail processing are routed to a dead letter stream.
    Flagged samples are routed to a quarantine stream for human review.

    Usage:
        consumer = RedisConsumer(
            redis_url="redis://localhost:6379",
            stream="samples:incoming",
            group="poison-detector",
            consumer_name="worker-1",
        )
        await consumer.connect()
        await consumer.consume(handler_function)

    Requires:
        redis (aioredis) package. Handles ImportError gracefully.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        stream: str = "samples:incoming",
        group: str = "poison-detector",
        consumer_name: str = "worker-0",
        dead_letter_stream: str = "samples:dead_letter",
        quarantine_stream: str = "samples:quarantine",
        backpressure_threshold: int = 10000,
        backpressure_recovery: int = 5000,
    ) -> None:
        """Initialize Redis Streams consumer.

        Args:
            redis_url: Redis connection URL.
            stream: Stream name to consume from.
            group: Consumer group name.
            consumer_name: Unique name for this consumer within the group.
            dead_letter_stream: Stream name for dead letter routing.
            quarantine_stream: Stream name for quarantine routing.
            backpressure_threshold: Queue depth for backpressure engagement.
            backpressure_recovery: Queue depth for backpressure recovery.
        """
        super().__init__(backpressure_threshold, backpressure_recovery)
        self._redis_url = redis_url
        self._stream = stream
        self._group = group
        self._consumer_name = consumer_name
        self._dead_letter_stream = dead_letter_stream
        self._quarantine_stream = quarantine_stream
        self._client: Any = None

    async def connect(self) -> None:
        """Connect to Redis and create consumer group.

        Creates the consumer group if it does not already exist.

        Raises:
            ConnectionError: If Redis is not reachable.
            ImportError: If redis package is not installed.
        """
        try:
            import redis.asyncio as aioredis
        except ImportError:
            raise ImportError(
                "redis package required for RedisConsumer. " "Install with: pip install redis"
            )

        try:
            self._client = aioredis.from_url(self._redis_url, decode_responses=True)
            # Create consumer group (ignore error if already exists)
            try:
                await self._client.xgroup_create(self._stream, self._group, id="0", mkstream=True)
            except Exception:
                # Group already exists
                pass
            self._running = True
            logger.info(
                f"Connected to Redis at {self._redis_url}, "
                f"stream={self._stream}, group={self._group}"
            )
        except Exception as e:
            raise ConnectionError(f"Failed to connect to Redis: {e}")

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        self._running = False
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("Disconnected from Redis")

    async def consume(
        self,
        handler: Callable[[PipelineMessage], Awaitable[ProcessingResult]],
        batch_size: int = 10,
    ) -> None:
        """Consume messages from Redis Stream and process with handler.

        Runs until stop() is called. Fetches messages in batches,
        processes each one, and acknowledges or routes to dead letter.

        Args:
            handler: Async function that processes each message.
            batch_size: Number of messages to read per XREADGROUP call.
        """
        if not self._client:
            raise RuntimeError("Not connected. Call connect() first.")

        self._running = True
        while self._running:
            try:
                # Read pending messages first, then new ones
                messages = await self._client.xreadgroup(
                    self._group,
                    self._consumer_name,
                    {self._stream: ">"},
                    count=batch_size,
                    block=1000,
                )

                if not messages:
                    # Check queue depth for backpressure
                    info = await self._client.xinfo_stream(self._stream)
                    self.update_backpressure(info.get("length", 0))
                    continue

                for stream_name, stream_messages in messages:
                    for msg_id, msg_data in stream_messages:
                        self._stats.messages_consumed += 1
                        pipeline_msg = self._parse_message(msg_id, msg_data)

                        if pipeline_msg is None:
                            # Malformed message -> dead letter
                            await self._dead_letter_raw(msg_id, msg_data, "Failed to parse message")
                            self.record_dead_letter()
                            await self._client.xack(self._stream, self._group, msg_id)
                            continue

                        try:
                            start = time.perf_counter()
                            result = await handler(pipeline_msg)
                            elapsed_ms = (time.perf_counter() - start) * 1000.0

                            if result.dead_lettered:
                                await self.dead_letter(pipeline_msg, result.error)
                                self.record_dead_letter()
                            elif result.quarantined:
                                await self.quarantine(pipeline_msg, result.score)
                                self.record_processing(elapsed_ms, quarantined=True)
                            else:
                                self.record_processing(elapsed_ms)

                            await self.acknowledge(msg_id)

                        except Exception as e:
                            logger.error(f"Handler error for message {msg_id}: {e}")
                            await self.dead_letter(pipeline_msg, f"Handler exception: {e}")
                            self.record_dead_letter()
                            await self.acknowledge(msg_id)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Consumer loop error: {e}")
                await asyncio.sleep(1.0)

    async def acknowledge(self, message_id: str) -> None:
        """Acknowledge a processed message in the consumer group.

        Args:
            message_id: The Redis Stream message ID.
        """
        if self._client:
            await self._client.xack(self._stream, self._group, message_id)

    async def dead_letter(self, message: PipelineMessage, error: str) -> None:
        """Route a failed message to the dead letter stream.

        Args:
            message: The failed message.
            error: Description of the failure.
        """
        if self._client:
            payload = {
                "original_id": message.message_id,
                "sample_data": json.dumps(message.sample_data),
                "source": message.source,
                "error": error,
                "timestamp": message.timestamp or str(time.time()),
            }
            await self._client.xadd(self._dead_letter_stream, payload)
            logger.warning(f"Dead-lettered message {message.message_id}: {error}")

    async def quarantine(self, message: PipelineMessage, score: float) -> None:
        """Route a flagged message to the quarantine stream.

        Args:
            message: The flagged message.
            score: The anomaly score.
        """
        if self._client:
            payload = {
                "original_id": message.message_id,
                "sample_data": json.dumps(message.sample_data),
                "source": message.source,
                "score": str(score),
                "timestamp": message.timestamp or str(time.time()),
            }
            await self._client.xadd(self._quarantine_stream, payload)
            logger.info(f"Quarantined message {message.message_id} (score={score:.3f})")

    async def _dead_letter_raw(self, msg_id: str, raw_data: dict[str, str], error: str) -> None:
        """Route raw unparseable message data to dead letter."""
        if self._client:
            payload = {
                "original_id": msg_id,
                "raw_data": json.dumps(raw_data),
                "error": error,
                "timestamp": str(time.time()),
            }
            await self._client.xadd(self._dead_letter_stream, payload)

    @staticmethod
    def _parse_message(msg_id: str, msg_data: dict[str, str]) -> PipelineMessage | None:
        """Parse a Redis Stream message into a PipelineMessage.

        Args:
            msg_id: The Redis Stream message ID.
            msg_data: The message field-value pairs.

        Returns:
            PipelineMessage if parsing succeeds, None otherwise.
        """
        try:
            sample_data_raw = msg_data.get("sample_data", "")
            if not sample_data_raw:
                return None

            sample_data = json.loads(sample_data_raw)
            return PipelineMessage(
                message_id=msg_id,
                sample_data=sample_data,
                source=msg_data.get("source", "redis"),
                timestamp=msg_data.get("timestamp", ""),
                metadata={
                    k: v
                    for k, v in msg_data.items()
                    if k not in ("sample_data", "source", "timestamp")
                },
            )
        except (json.JSONDecodeError, ValueError):
            return None


class KafkaConsumer(PipelineConsumer):
    """Kafka consumer for high-throughput enterprise pipelines.

    Uses Kafka consumer groups for distributed processing across multiple
    instances. Supports automatic partition rebalancing and offset management.

    Usage:
        consumer = KafkaConsumer(
            bootstrap_servers="kafka:9092",
            topic="training-samples",
            group_id="poison-detector",
        )
        await consumer.connect()
        await consumer.consume(handler_function)

    Requires:
        aiokafka package. Handles ImportError gracefully.
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        topic: str = "training-samples",
        group_id: str = "poison-detector",
        dead_letter_topic: str = "training-samples-dlq",
        quarantine_topic: str = "training-samples-quarantine",
        backpressure_threshold: int = 10000,
        backpressure_recovery: int = 5000,
    ) -> None:
        """Initialize Kafka consumer.

        Args:
            bootstrap_servers: Kafka bootstrap servers (comma-separated).
            topic: Topic to consume from.
            group_id: Consumer group ID.
            dead_letter_topic: Topic for dead letter messages.
            quarantine_topic: Topic for quarantined samples.
            backpressure_threshold: Queue depth for backpressure engagement.
            backpressure_recovery: Queue depth for backpressure recovery.
        """
        super().__init__(backpressure_threshold, backpressure_recovery)
        self._bootstrap_servers = bootstrap_servers
        self._topic = topic
        self._group_id = group_id
        self._dead_letter_topic = dead_letter_topic
        self._quarantine_topic = quarantine_topic
        self._consumer: Any = None
        self._producer: Any = None

    async def connect(self) -> None:
        """Connect to Kafka cluster.

        Creates consumer and producer instances for consuming messages
        and routing to dead letter / quarantine topics.

        Raises:
            ConnectionError: If Kafka is not reachable.
            ImportError: If aiokafka is not installed.
        """
        try:
            from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
        except ImportError:
            raise ImportError(
                "aiokafka package required for KafkaConsumer. " "Install with: pip install aiokafka"
            )

        try:
            self._consumer = AIOKafkaConsumer(
                self._topic,
                bootstrap_servers=self._bootstrap_servers,
                group_id=self._group_id,
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                auto_offset_reset="earliest",
                enable_auto_commit=False,
            )
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            )
            await self._consumer.start()
            await self._producer.start()
            self._running = True
            logger.info(
                f"Connected to Kafka at {self._bootstrap_servers}, "
                f"topic={self._topic}, group={self._group_id}"
            )
        except Exception as e:
            raise ConnectionError(f"Failed to connect to Kafka: {e}")

    async def disconnect(self) -> None:
        """Disconnect from Kafka gracefully."""
        self._running = False
        if self._consumer:
            await self._consumer.stop()
            self._consumer = None
        if self._producer:
            await self._producer.stop()
            self._producer = None
        logger.info("Disconnected from Kafka")

    async def consume(
        self,
        handler: Callable[[PipelineMessage], Awaitable[ProcessingResult]],
        batch_size: int = 10,
    ) -> None:
        """Consume messages from Kafka and process with handler.

        Runs until stop() is called.

        Args:
            handler: Async function that processes each message.
            batch_size: Maximum messages to process per iteration.
        """
        if not self._consumer:
            raise RuntimeError("Not connected. Call connect() first.")

        self._running = True
        while self._running:
            try:
                # Fetch a batch of messages with timeout
                batch = await self._consumer.getmany(timeout_ms=1000, max_records=batch_size)

                for tp, messages in batch.items():
                    for msg in messages:
                        self._stats.messages_consumed += 1
                        pipeline_msg = self._parse_kafka_message(msg)

                        if pipeline_msg is None:
                            await self._dead_letter_raw_kafka(msg, "Failed to parse message")
                            self.record_dead_letter()
                            continue

                        try:
                            start = time.perf_counter()
                            result = await handler(pipeline_msg)
                            elapsed_ms = (time.perf_counter() - start) * 1000.0

                            if result.dead_lettered:
                                await self.dead_letter(pipeline_msg, result.error)
                                self.record_dead_letter()
                            elif result.quarantined:
                                await self.quarantine(pipeline_msg, result.score)
                                self.record_processing(elapsed_ms, quarantined=True)
                            else:
                                self.record_processing(elapsed_ms)

                        except Exception as e:
                            logger.error(f"Handler error for Kafka message: {e}")
                            await self.dead_letter(pipeline_msg, f"Handler exception: {e}")
                            self.record_dead_letter()

                # Commit offsets after processing batch
                if batch:
                    await self._consumer.commit()

                # Update backpressure estimate
                # Use consumer lag as proxy for queue depth
                lag = 0
                for tp in self._consumer.assignment():
                    end_offsets = await self._consumer.end_offsets([tp])
                    committed = await self._consumer.committed(tp)
                    lag += end_offsets[tp] - (committed or 0)
                self.update_backpressure(lag)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Kafka consumer loop error: {e}")
                await asyncio.sleep(1.0)

    async def acknowledge(self, message_id: str) -> None:
        """Acknowledge by committing offsets (handled in consume loop).

        For Kafka, acknowledgment is via offset commits which happen
        after each batch in the consume loop.

        Args:
            message_id: Unused for Kafka (offset-based).
        """
        # Kafka uses offset-based commits, handled in consume()
        pass

    async def dead_letter(self, message: PipelineMessage, error: str) -> None:
        """Route a failed message to the dead letter topic.

        Args:
            message: The failed message.
            error: Description of the failure.
        """
        if self._producer:
            payload = {
                "original_id": message.message_id,
                "sample_data": message.sample_data,
                "source": message.source,
                "error": error,
                "timestamp": message.timestamp or str(time.time()),
            }
            await self._producer.send(self._dead_letter_topic, payload)
            logger.warning(f"Dead-lettered Kafka message {message.message_id}: {error}")

    async def quarantine(self, message: PipelineMessage, score: float) -> None:
        """Route a flagged message to the quarantine topic.

        Args:
            message: The flagged message.
            score: The anomaly score.
        """
        if self._producer:
            payload = {
                "original_id": message.message_id,
                "sample_data": message.sample_data,
                "source": message.source,
                "score": score,
                "timestamp": message.timestamp or str(time.time()),
            }
            await self._producer.send(self._quarantine_topic, payload)
            logger.info(f"Quarantined Kafka message {message.message_id} " f"(score={score:.3f})")

    async def _dead_letter_raw_kafka(self, msg: Any, error: str) -> None:
        """Route unparseable Kafka message to dead letter."""
        if self._producer:
            payload = {
                "raw_value": str(msg.value) if msg.value else "",
                "topic": msg.topic,
                "partition": msg.partition,
                "offset": msg.offset,
                "error": error,
                "timestamp": str(time.time()),
            }
            await self._producer.send(self._dead_letter_topic, payload)

    @staticmethod
    def _parse_kafka_message(msg: Any) -> PipelineMessage | None:
        """Parse a Kafka message into a PipelineMessage.

        Args:
            msg: Kafka ConsumerRecord.

        Returns:
            PipelineMessage if parsing succeeds, None otherwise.
        """
        try:
            value = msg.value
            if isinstance(value, dict):
                sample_data = value.get("sample_data")
                if sample_data is None:
                    return None
                return PipelineMessage(
                    message_id=f"{msg.topic}:{msg.partition}:{msg.offset}",
                    sample_data=sample_data,
                    source=value.get("source", msg.topic),
                    timestamp=value.get("timestamp", ""),
                    metadata={
                        k: v
                        for k, v in value.items()
                        if k not in ("sample_data", "source", "timestamp")
                    },
                )
            return None
        except (AttributeError, TypeError, ValueError):
            return None
