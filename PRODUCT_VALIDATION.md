# Product Validation

## Product boundary
Ingestion-boundary screening for anomalous or suspicious training data. It is a defense-in-depth signal, not a guarantee that training data is clean.

## Real-world validation ladder
1. Synthetic controlled attacks for exact regression behavior.
2. Public real-dataset benchmark with controlled label corruption. CI must reject an all-clear/all-flagged degeneration and requires a non-zero true-positive signal on the deterministic Wisconsin Diagnostic Breast Cancer benchmark.
3. Streaming/Kafka path and quarantine-state integration tests.
4. Drift and slow-change scenarios separated from point anomalies.
5. External pilot on a real data pipeline with labeled analyst review.

## Evidence rules
Synthetic F1 and public-dataset F1 are reported separately. Throughput is hardware-scoped. Clean-label/backdoor/low-rate failures remain visible rather than averaged away.
