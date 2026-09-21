# Benchmark Methodology

Performance numbers in this repository must be tied to a generated JSON artifact, the exact code revision, and the execution environment.

## Streaming microbenchmark

`benchmarks/throughput_tracker.py` now imports the shipped `poison_detector.StreamingDetector` directly. It does **not** fall back to a test stub.

The streaming measurement is deliberately scoped to the no-refit `score_sample()` fast path: 20 features by default, single-sample scoring, periodic IsolationForest refits disabled for the timed window, and network/Kafka/Redis/API/serialization overhead excluded.

This is a microbenchmark, not default deployment throughput. The default detector periodically refits IsolationForest, which can dominate wall-clock time.

## Efficacy fixture

The benchmark invokes the shipped `poison_detector.detect(..., method="ensemble")` implementation against seeded synthetic backdoor, label-flip, and subtle fixtures. Those AUC values are regression measurements for the fixture generator, not real-world poisoning-detection rates.

## Evidence policy

Do not copy a throughput or latency value into the README, résumé, portfolio, or dashboard unless the corresponding benchmark JSON artifact and environment are available. A hardware-independent CI performance SLA is intentionally not used.

The previous local "~12,400 samples/sec" note did not record a commit SHA and the old benchmark script could silently fall back to a stub implementation. It is therefore historical context only and is not a current verified claim.
