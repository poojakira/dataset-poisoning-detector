# Changelog - dataset-poisoning-detector

## [1.0.0] - 2026-07-22

### Changed - ATT&CK v19 Migration

#### New Technique Coverage Added
- **T1685** (Disable or Modify Tools): Added to `anomaly_suppression` (replaces T1562 pattern)
- **T1688** (Safe Mode Boot): Added to `sleeper_agent_pattern`

#### New Rule Added
- **anomaly_suppression**: ["T1685", "T1027"] - NEW rule for T1685 coverage

#### Rule Table Updates
```python
# BEFORE
"sleeper_agent_pattern": ["T1195.001", "T1497"],
# (no anomaly_suppression rule)

# AFTER
"sleeper_agent_pattern": ["T1195.001", "T1497", "T1688"],
"anomaly_suppression": ["T1685", "T1027"],
```

### Added
- T1685 coverage for anomaly suppression (defense impairment analog)
- T1688 Safe Mode Boot as evasion analog for sleeper agents

### Migration
See [attack-v19-core MIGRATION_GUIDE.md](../attack-v19-core/MIGRATION_GUIDE.md) for full migration steps.