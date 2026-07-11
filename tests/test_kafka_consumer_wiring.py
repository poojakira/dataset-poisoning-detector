"""Regression guard for the Kafka consumer's detector wiring.

examples/kafka_consumer.py cannot be imported directly in CI (it requires the
optional confluent_kafka dependency), so this test reconstructs the exact
detector wiring the consumer uses and asserts the constructors accept those
kwargs. It specifically pins the historically-buggy call
``ConceptDriftDetector(sensitivity=...)`` to the correct ``delta=`` keyword so
the crash-on-first-message bug cannot silently return.
"""

import inspect

from poison_detector.drift import ConceptDriftDetector
from poison_detector.fingerprint import SampleFingerprinter
from poison_detector.stream import StreamingDetector


def test_concept_drift_detector_uses_delta_not_sensitivity():
    params = inspect.signature(ConceptDriftDetector.__init__).parameters
    assert "delta" in params
    assert "sensitivity" not in params


def test_kafka_consumer_detector_wiring_constructs():
    """Mirror the three-detector setup from PoisonDetectionConsumer.__init__."""
    drift_sensitivity = 0.01
    detector = StreamingDetector(
        window_size=10000, contamination=0.05, drift_sensitivity=drift_sensitivity
    )
    drift_detector = ConceptDriftDetector(delta=drift_sensitivity)
    fingerprinter = SampleFingerprinter(similarity_threshold=0.95)

    # Smoke: the wiring actually scores a sample without raising.
    result = detector.score_sample([1.0, 2.0, 3.0])
    drift_detector.update([1.0, 2.0, 3.0])
    assert isinstance(fingerprinter.is_duplicate([1.0, 2.0, 3.0]), bool)
    assert 0.0 <= result.score <= 1.0
