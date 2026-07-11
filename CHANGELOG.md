# Changelog

## 0.1.0 (2024-01-15)

### Added
- Z-score anomaly detection (pure Python, no numpy dependency)
- IQR fencing anomaly detection (pure Python)
- Isolation Forest wrapper with normalized 0-1 scoring
- Ensemble detection via majority vote across all three methods
- Feature-level attribution for understanding why samples are flagged
- Report formatting: human-readable, JSON, and CSV export
- 13 unit tests covering all detection methods
- CI pipeline via GitHub Actions
