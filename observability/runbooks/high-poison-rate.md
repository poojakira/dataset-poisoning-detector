# Runbook: High Poison Rate Alert

## Alert

**Name:** PoisonRateHigh  
**Severity:** Critical  
**Condition:** Poison detection rate exceeds 10% of processed samples for 5+ minutes

## Symptoms

- The `PoisonRateHigh` alert fires in PagerDuty/Slack
- The Grafana "Current Poison Rate" gauge shows values above 0.1 (10%)
- Increased entries in the quarantine storage backend
- Downstream consumers may report elevated rejection rates

## Diagnosis Steps

1. **Check data source changes:**
   - Were there recent deployments to upstream data producers?
   - Did a new data source get onboarded recently?
   - Check if the spike correlates with a specific `environment` label value

2. **Review quarantined samples:**
   ```bash
   # Query recent quarantine entries
   kubectl exec -it deploy/poison-detector -- \
     python -c "from poison_detector.storage import get_quarantine; print(get_quarantine(limit=20))"
   ```
   - Look for common patterns (same source IP, same feature distribution, repeated fingerprints)

3. **Check for drift correlation:**
   - Open Grafana and compare the drift score timeseries with the poison rate spike
   - If drift score is also elevated, this may indicate a distributional shift rather than targeted poisoning

4. **Check detector health:**
   - Verify the IsolationForest model is not stale (check refit latency and last refit timestamp)
   - Verify baseline size has not shrunk unexpectedly

## Possible Causes

| Cause | Likelihood | Indicators |
|-------|-----------|------------|
| Active data poisoning attack | High if sudden spike | Concentrated from few sources, unusual feature patterns |
| Data source quality degradation | Medium | Gradual increase, correlates with upstream deployment |
| Miscalibrated thresholds | Low | Occurs after model refit, high false positive rate on manual review |
| Model staleness | Medium | Long time since last refit, drift score also elevated |
| Legitimate distribution change | Medium | Correlates with known business events (e.g., product launch) |

## Remediation Actions

### Immediate (within 5 minutes)

1. **Investigate quarantined samples** - manually inspect 10-20 recent quarantine entries
2. **Determine if this is a true positive** - are the flagged samples genuinely malicious?

### If confirmed attack

1. **Identify the source** - check if poisoned samples share a common origin
2. **Block the source** - add source to blocklist if identifiable
3. **Preserve evidence** - snapshot quarantine data for forensic analysis
4. **Escalate to security team** - page the security on-call engineer
5. **Notify downstream consumers** - alert teams whose models consume this data

### If false positive

1. **Adjust thresholds** - increase the anomaly score threshold temporarily
   ```yaml
   # In detector config
   anomaly_threshold: -0.3  # was -0.5, less sensitive
   ```
2. **Refit the model** - trigger a manual refit with verified clean data
3. **Review baseline** - ensure the baseline training data is representative of current legitimate traffic

### If data quality issue

1. **Contact upstream data team** - coordinate to fix the data source
2. **Temporarily increase tolerance** - adjust thresholds while upstream fixes deploy
3. **Add the new distribution to baseline** - if the data change is legitimate

## Escalation Path

| Time Elapsed | Action |
|-------------|--------|
| 0-5 min | On-call engineer investigates using this runbook |
| 5-15 min | If confirmed attack, page security team lead |
| 15-30 min | If unresolved, escalate to ML platform team lead |
| 30+ min | Incident commander engaged, cross-team war room |

## Related Alerts

- **DriftSpike** - often fires in correlation; check if drift preceded the poison rate increase
- **QueueBacklog** - may fire if quarantine operations slow down the pipeline
- **HighErrorRate** - may fire if quarantine storage is full

## Contact

- ML Security Team: #ml-security-oncall
- Platform Team: #platform-oncall
- Security Incident Response: #security-ir
