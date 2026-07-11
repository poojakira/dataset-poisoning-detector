# Runbook: Drift Score Alert

## Alert

**Name:** DriftSpike  
**Severity:** Warning  
**Condition:** Drift score exceeds 0.8 for 2+ minutes

## Symptoms

- The `DriftSpike` alert fires
- Grafana "Drift Score" panel shows sustained values above 0.8
- The `poison_detector_drift_events_total` counter is incrementing
- Poison rate may or may not be elevated (depends on cause)

## Diagnosis Steps

### 1. Distinguish legitimate drift from adversarial drift

**Check correlation with known events:**
- Was there a scheduled data source migration?
- Did a new feature or product launch recently change user behavior?
- Is there a seasonal pattern (end of quarter, holiday traffic)?

**Check drift characteristics:**
```bash
# Check if drift is gradual or sudden
# Look at drift score over last 24h in Grafana
# Gradual: slope increases steadily over hours
# Sudden: step function jump in drift score
```

| Pattern | Likely Cause |
|---------|-------------|
| Sudden spike, single source | Data pipeline issue or targeted attack |
| Gradual increase over days | Legitimate concept drift or slow poisoning |
| Periodic spikes | Batch processing or scheduled data loads |
| Correlated with poison rate | Possible adversarial drift (attacker shifting baseline) |

### 2. Check data source metadata

```bash
# Review recent data sources and their characteristics
kubectl exec -it deploy/poison-detector -- \
  python -c "
from poison_detector.metrics import DRIFT_SCORE
# Check per-environment drift scores
"
```

- Identify which environment(s) are affected
- Check if drift is isolated to specific data sources or features
- Compare feature distributions between current window and baseline

### 3. Analyze the drift direction

- Is the distribution shifting toward known attack patterns?
- Are specific features drifting more than others?
- Does the new distribution match any known legitimate business scenario?

## Decision Framework

```
Is the drift correlated with known business changes?
|
+-- YES --> Is the change expected to be permanent?
|           |
|           +-- YES --> Update baseline with verified clean data
|           +-- NO  --> Wait for transient event to pass, suppress alert
|
+-- NO  --> Is the drift gradual (over days)?
            |
            +-- YES --> Possible slow poisoning campaign
            |           - Investigate as potential attack
            |           - Check if poison rate is subtly increasing
            |           - Review quarantined samples for patterns
            |
            +-- NO  --> Sudden drift, unknown cause
                        - Treat as potential attack until proven otherwise
                        - Escalate to security team
                        - Snapshot current state for forensics
```

## Remediation Actions

### If legitimate drift (confirmed benign cause)

1. **Reset baseline with verified clean data:**
   ```bash
   # Collect verified clean samples from the new distribution
   kubectl exec -it deploy/poison-detector -- \
     python -c "
   from poison_detector.stream import StreamingDetector
   # Trigger baseline reset with verified data
   "
   ```

2. **Adjust sensitivity if needed:**
   ```yaml
   # In detector config
   drift_threshold: 0.9  # was 0.8, temporarily less sensitive
   ```

3. **Document the drift event** - record what caused it for future reference

### If suspected adversarial drift (slow poisoning)

1. **Do NOT reset the baseline** - attacker may be trying to shift it
2. **Alert security team immediately** - this is a potential active attack
3. **Increase monitoring sensitivity:**
   ```yaml
   drift_threshold: 0.6  # Lower threshold to catch further movement
   ```
4. **Quarantine all samples in the drift window** - do not let them influence the model
5. **Collect forensic evidence:**
   - Snapshot the current baseline
   - Snapshot the drifting samples
   - Record timestamps and source metadata

### If uncertain

1. **Maintain current baseline** - do not update until cause is determined
2. **Increase sample inspection rate** - manually review more quarantined samples
3. **Set up canary comparison** - run a parallel detector with a known-good baseline
4. **Schedule investigation** - if not immediately dangerous, investigate within 24h

## Escalation Path

| Time Elapsed | Action |
|-------------|--------|
| 0-5 min | On-call engineer reviews drift characteristics |
| 5-15 min | Determine if benign or suspicious using decision framework |
| 15-30 min | If suspicious, page security team |
| 30+ min | If confirmed adversarial, invoke incident response |

## Key Metrics to Monitor During Investigation

- `poison_detector_drift_score` - is it still rising?
- `poison_detector_poison_rate` - is poison rate correlated?
- `poison_detector_baseline_size` - is baseline being affected?
- `poison_detector_samples_processed_total` - is traffic volume unusual?
- `poison_detector_drift_events_total` - how many drift events in window?

## Prevention

- Regularly rotate and verify baseline data
- Set up automated baseline freshness checks
- Monitor drift score trends over weeks, not just real-time
- Implement graduated thresholds (0.5 = informational, 0.8 = warning, 0.95 = critical)

## Related Alerts

- **PoisonRateHigh** - often correlated; check both together
- **QueueBacklog** - drift investigation should not slow down processing

## Contact

- ML Security Team: #ml-security-oncall
- Data Platform Team: #data-platform
- Security Incident Response: #security-ir (if adversarial drift confirmed)
