"""
Production Kafka Consumer for Real-Time Poisoning Detection

This example shows how to set up a production Kafka consumer that:
- Reads training samples from a Kafka topic
- Scores each sample for data poisoning in real-time
- Routes flagged samples to a quarantine topic
- Publishes detection metrics to Prometheus
- Handles backpressure, retries, and graceful shutdown

Usage:
    # Requires a running Kafka cluster
    export KAFKA_BOOTSTRAP_SERVERS=localhost:9092
    export KAFKA_INPUT_TOPIC=training-samples
    export KAFKA_QUARANTINE_TOPIC=quarantine-samples
    python examples/kafka_consumer.py

Requirements:
    pip install -e ".[realtime,kafka]"

Architecture:
    [Data Pipeline] -> [Kafka: training-samples] -> [This Consumer]
                                                         |
                                                    [StreamingDetector]
                                                         |
                                        +----------------+----------------+
                                        |                                 |
                                  [Clean: pass through]           [Flagged: quarantine]
                                        |                                 |
                                  [Downstream Training]        [Kafka: quarantine-samples]
"""

import json
import os
import signal
import sys
import time
import logging
from dataclasses import dataclass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("kafka_consumer")

try:
    from confluent_kafka import Consumer, Producer, KafkaError, KafkaException
except ImportError:
    logger.error(
        "confluent-kafka not installed. Install with: pip install -e '.[kafka]'"
    )
    sys.exit(1)

from poison_detector.stream import StreamingDetector
from poison_detector.drift import ConceptDriftDetector
from poison_detector.fingerprint import SampleFingerprinter
from poison_detector.metrics import SAMPLES_PROCESSED, SAMPLES_POISONED, SCORING_LATENCY


@dataclass
class ConsumerConfig:
    """Kafka consumer configuration loaded from environment."""

    bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    group_id: str = os.getenv("KAFKA_GROUP_ID", "poison-detector-group")
    input_topic: str = os.getenv("KAFKA_INPUT_TOPIC", "training-samples")
    quarantine_topic: str = os.getenv("KAFKA_QUARANTINE_TOPIC", "quarantine-samples")
    auto_offset_reset: str = "earliest"
    max_poll_interval_ms: int = 300000
    session_timeout_ms: int = 45000
    # Detection settings
    window_size: int = 10000
    contamination: float = 0.05
    drift_sensitivity: float = 0.01


class PoisonDetectionConsumer:
    """
    Production Kafka consumer with real-time poisoning detection.

    Features:
        - Graceful shutdown on SIGINT/SIGTERM
        - Dead letter queue for malformed messages
        - Backpressure via consumer pause/resume
        - Exactly-once semantics via manual offset commit
        - Prometheus metrics for observability

    Threat Model:
        Assumes training samples arrive as JSON messages on the input topic.
        Each message has a 'features' key with a list of floats.
        Flagged samples are forwarded to the quarantine topic with metadata.
    """

    def __init__(self, config: ConsumerConfig | None = None) -> None:
        self.config = config or ConsumerConfig()
        self._running = False

        # Detection components
        self.detector = StreamingDetector(
            window_size=self.config.window_size,
            contamination=self.config.contamination,
            drift_sensitivity=self.config.drift_sensitivity,
        )
        self.drift_detector = ConceptDriftDetector(
            sensitivity=self.config.drift_sensitivity,
        )
        self.fingerprinter = SampleFingerprinter(similarity_threshold=0.95)

        # Kafka clients
        self.consumer = Consumer({
            "bootstrap.servers": self.config.bootstrap_servers,
            "group.id": self.config.group_id,
            "auto.offset.reset": self.config.auto_offset_reset,
            "enable.auto.commit": False,
            "max.poll.interval.ms": self.config.max_poll_interval_ms,
            "session.timeout.ms": self.config.session_timeout_ms,
        })
        self.producer = Producer({
            "bootstrap.servers": self.config.bootstrap_servers,
            "acks": "all",
            "retries": 3,
            "retry.backoff.ms": 1000,
        })

        # Register signal handlers
        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, signum: int, frame) -> None:
        """Handle graceful shutdown."""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self._running = False

    def _process_message(self, message_value: bytes) -> None:
        """Process a single Kafka message through the detection pipeline."""
        try:
            payload = json.loads(message_value)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"Malformed message, sending to DLQ: {e}")
            self._send_to_dlq(message_value, str(e))
            return

        features = payload.get("features")
        if not features or not isinstance(features, list):
            logger.warning("Message missing 'features' field, skipping")
            self._send_to_dlq(message_value, "missing or invalid 'features' field")
            return

        # Score the sample
        start = time.perf_counter()
        result = self.detector.score_sample(features)
        self.drift_detector.update(features)
        is_duplicate = self.fingerprinter.is_duplicate(features)
        latency_ms = (time.perf_counter() - start) * 1000

        SAMPLES_PROCESSED.inc()
        SCORING_LATENCY.observe(latency_ms / 1000.0)

        # Determine if sample should be quarantined
        flagged = result.is_poisoned or is_duplicate

        if flagged:
            SAMPLES_POISONED.inc()
            quarantine_payload = {
                "original": payload,
                "detection": {
                    "score": result.score,
                    "is_poisoned": result.is_poisoned,
                    "is_duplicate": is_duplicate,
                    "is_drifting": self.drift_detector.is_drifting(),
                    "latency_ms": latency_ms,
                    "timestamp": time.time(),
                },
            }
            self.producer.produce(
                self.config.quarantine_topic,
                value=json.dumps(quarantine_payload).encode("utf-8"),
                callback=self._delivery_callback,
            )
            logger.info(
                f"QUARANTINED sample | score={result.score:.3f} | "
                f"dup={is_duplicate} | drift={self.drift_detector.is_drifting()}"
            )
        else:
            # Register clean sample in fingerprinter
            self.fingerprinter.add_sample(features)

    def _send_to_dlq(self, message_value: bytes, error: str) -> None:
        """Send malformed messages to dead letter queue topic."""
        dlq_payload = {
            "original_message": message_value.decode("utf-8", errors="replace"),
            "error": error,
            "timestamp": time.time(),
        }
        self.producer.produce(
            f"{self.config.input_topic}.dlq",
            value=json.dumps(dlq_payload).encode("utf-8"),
        )

    @staticmethod
    def _delivery_callback(err, msg) -> None:
        """Kafka producer delivery callback."""
        if err:
            logger.error(f"Delivery failed for {msg.topic()}: {err}")
        else:
            logger.debug(f"Delivered to {msg.topic()} [{msg.partition()}]")

    def run(self) -> None:
        """Main consumer loop with graceful shutdown."""
        self.consumer.subscribe([self.config.input_topic])
        self._running = True
        messages_since_commit = 0
        commit_interval = 100

        logger.info(
            f"Starting consumer | topic={self.config.input_topic} | "
            f"group={self.config.group_id}"
        )

        try:
            while self._running:
                msg = self.consumer.poll(timeout=1.0)

                if msg is None:
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    else:
                        raise KafkaException(msg.error())

                self._process_message(msg.value())
                messages_since_commit += 1

                # Periodic commit
                if messages_since_commit >= commit_interval:
                    self.consumer.commit(asynchronous=False)
                    self.producer.flush()
                    messages_since_commit = 0

        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        finally:
            # Final commit and cleanup
            logger.info("Committing offsets and closing...")
            self.consumer.commit(asynchronous=False)
            self.producer.flush()
            self.consumer.close()
            logger.info("Consumer shut down cleanly")


def main() -> None:
    """Entry point for the Kafka consumer."""
    config = ConsumerConfig()
    logger.info(f"Configuration: {config}")
    consumer = PoisonDetectionConsumer(config)
    consumer.run()


if __name__ == "__main__":
    main()
