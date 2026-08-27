# Incident Runbook — Dataset Poisoning Detector

Operational runbook for common incidents in the streaming detection pipeline.

---

## Table of Contents

1. [High False Positive Rate in Streaming](#1-high-false-positive-rate-in-streaming)
2. [Kafka Consumer Lag Building Up](#2-kafka-consumer-lag-building-up)
3. [Drift Detector Flapping](#3-drift-detector-flapping)
4. [Quarantine Storage Filling Up](#4-quarantine-storage-filling-up)

---

## 1. High False Positive Rate in Streaming

### Symptoms
- Alert volume spikes unexpectedly
- PagerDuty/Slack channels flooded with poison alerts
- Quarantine store growing rapidly with samples later confirmed clean
- Metrics show `samples_flagged / samples_processed` ratio > 10%

### Impact
- Analyst fatigue — real poisoned samples get buried
- Quarantine storage fills faster (see Scenario 4)
- Downstream training pipelines stalled waiting for review

### Diagnosis

```bash
# Check current false positive rate
curl http://detector:8080/metrics | grep -E "flagged|processed"

# Inspect recent quarantined samples
sqlite3 /var/lib/detector/quarantine.db \
  "SELECT id, score, reason, quarantined_at FROM quarantine ORDER BY quarantined_at DESC LIMIT 20;"

# Check if input distribution shifted
curl http://detector:8080/drift-status
```

**Root cause checklist:**
- [ ] Did the upstream data source change format or schema?
- [ ] Did a model retrain reset the feature space?
- [ ] Is the detection threshold set too low for this data modality?
- [ ] Did the drift detector update the baseline to an anomalous window?

### Resolution

**Immediate (< 5 min):**
1. Raise the detection threshold temporarily:
   ```bash
   curl -X POST http://detector:8080/config \
     -d '{"threshold": 5.0}'  # default is 3.0
   ```
2. Pause alerting for non-critical severities:
   ```bash
   curl -X POST http://detector:8080/alerting/pause \
     -d '{"min_severity": "error"}'
   ```

**Short-term (< 1 hour):**
1. Inspect the feature distribution of recent samples vs. the baseline window
2. If upstream data changed: reset the drift baseline:
   ```bash
   curl -X POST http://detector:8080/drift/reset-baseline
   ```
3. Review and bulk-approve quarantined samples from the spike period:
   ```bash
   python scripts/bulk_review.py --since "2h ago" --action approve
   ```

**Long-term:**
- Tune threshold per data modality (tabular vs. image vs. text)
- Implement adaptive thresholding based on rolling FP rate
- Add a human-in-the-loop feedback signal to update the model

### Escalation
- If FP rate > 50% for > 30 minutes: page on-call ML engineer
- If source of distribution shift cannot be identified: escalate to data platform team

---

## 2. Kafka Consumer Lag Building Up

### Symptoms
- Grafana alert: consumer lag > 10,000 messages
- Detection results delayed (stale timestamps in quarantine)
- Metrics show `messages_received` rate dropping or flat
- Kafka consumer group shows increasing offset lag

### Impact
- Poisoned samples may reach training pipeline before being flagged
- SLA breach on detection latency (target: < 5 sec from ingestion)

### Diagnosis

```bash
# Check consumer lag
kafka-consumer-groups.sh --bootstrap-server kafka:9092 \
  --group poison-detector --describe

# Check detector health
curl http://detector:8080/health

# Check for processing errors
docker logs detector --since 10m 2>&1 | grep -i "error\|exception\|timeout"

# Check Redis connectivity (used for dedup cache)
redis-cli -h redis ping
```

**Root cause checklist:**
- [ ] Ingestion rate spiked (batch upload, replay, new data source)?
- [ ] Detector pod OOM-killed or restarting?
- [ ] Redis down (dedup lookups timing out)?
- [ ] Single slow method in ensemble blocking pipeline?
- [ ] Network partition between consumer and Kafka brokers?

### Resolution

**Immediate (< 5 min):**
1. Scale consumers horizontally:
   ```bash
   kubectl scale deployment detector --replicas=4
   ```
2. Check if Redis is responsive; restart if needed:
   ```bash
   kubectl rollout restart deployment redis
   ```

**Short-term (< 1 hour):**
1. If a single ensemble method is slow, disable it temporarily:
   ```bash
   curl -X POST http://detector:8080/config \
     -d '{"ensemble_methods": ["feature_space", "activation_clustering"]}'
   ```
2. Increase consumer batch size to improve throughput:
   ```bash
   curl -X POST http://detector:8080/config \
     -d '{"batch_size": 128}'  # default 64
   ```
3. If ingestion spike is temporary, wait for consumers to catch up after scaling.

**Long-term:**
- Set up auto-scaling based on consumer lag metric
- Implement circuit breaker for slow ensemble methods
- Add backpressure signaling to upstream producers
- Consider partitioning topic by data source for isolated scaling

### Escalation
- Lag > 100,000 and growing: page on-call + data platform team
- If training pipeline is consuming un-scanned data: trigger emergency training halt

---

## 3. Drift Detector Flapping

### Symptoms
- Alternating drift-detected / no-drift alerts in rapid succession
- Slack channel showing drift alerts every few minutes
- Metrics show `drift_triggered` toggling ON/OFF repeatedly
- Baseline resets happening too frequently

### Impact
- Alert fatigue (analysts ignore real drift events)
- Unstable threshold adjustments if auto-tuning is enabled
- Intermittent performance degradation during baseline recalculation

### Diagnosis

```bash
# Check drift history
curl http://detector:8080/drift/history?last=20

# Check drift score time series
curl http://detector:8080/metrics | grep drift_score

# Inspect window size vs data rate
curl http://detector:8080/config | jq '.drift_window'
```

**Root cause checklist:**
- [ ] Drift window too small relative to natural data variance?
- [ ] Cyclical pattern in data (e.g., time-of-day effects)?
- [ ] Sensitivity threshold too tight?
- [ ] Multiple data sources with different distributions feeding same topic?
- [ ] Baseline was set during anomalous period?

### Resolution

**Immediate (< 5 min):**
1. Suppress drift alerts temporarily:
   ```bash
   curl -X POST http://detector:8080/drift/suppress --data '{"duration_minutes": 30}'
   ```
2. Increase drift detection cooldown:
   ```bash
   curl -X POST http://detector:8080/config \
     -d '{"drift_cooldown_seconds": 300}'  # don't re-alert within 5 min
   ```

**Short-term (< 1 hour):**
1. Increase drift window size to smooth out variance:
   ```bash
   curl -X POST http://detector:8080/config \
     -d '{"drift_window": 1000}'  # default 200
   ```
2. Raise drift sensitivity threshold:
   ```bash
   curl -X POST http://detector:8080/config \
     -d '{"drift_threshold": 3.0}'  # default 2.0
   ```
3. Force reset baseline from known-good period:
   ```bash
   curl -X POST http://detector:8080/drift/reset-baseline \
     -d '{"source": "last_known_good", "timestamp": "2026-08-27T00:00:00Z"}'
   ```

**Long-term:**
- Implement hysteresis: require N consecutive windows above threshold before alerting
- Use CUSUM or Page-Hinkley test instead of simple z-score comparison
- Segment drift detection by data source/label class
- Add time-of-day and day-of-week seasonality modeling

### Escalation
- If drift is real (confirmed distribution shift): investigate upstream data pipeline
- If auto-tuning made bad threshold changes: disable auto-tuning, page ML engineer

---

## 4. Quarantine Storage Filling Up

### Symptoms
- Disk usage alert on quarantine volume (> 80% capacity)
- SQLite write errors in detector logs: `database or disk is full`
- New flagged samples being dropped silently
- Metrics show `quarantine_store_errors` incrementing

### Impact
- Flagged samples lost — cannot review or analyze poison attempts
- Detector may crash or degrade if writes fail unhandled
- Compliance risk: audit trail interrupted

### Diagnosis

```bash
# Check quarantine database size
ls -lh /var/lib/detector/quarantine.db
du -sh /var/lib/detector/

# Check total quarantined count and unreviewed backlog
sqlite3 /var/lib/detector/quarantine.db \
  "SELECT COUNT(*), SUM(CASE WHEN reviewed=0 THEN 1 ELSE 0 END) FROM quarantine;"

# Check disk space
df -h /var/lib/detector/

# Check quarantine growth rate (last 24h)
sqlite3 /var/lib/detector/quarantine.db \
  "SELECT COUNT(*) FROM quarantine WHERE quarantined_at > unixepoch() - 86400;"
```

**Root cause checklist:**
- [ ] High false positive rate filling storage with clean samples? (→ Scenario 1)
- [ ] Reviewed samples not being purged?
- [ ] Retention policy not configured or cron not running?
- [ ] Storage volume undersized for current ingestion rate?
- [ ] Actual poison campaign generating large volume of real alerts?

### Resolution

**Immediate (< 5 min):**
1. Purge already-reviewed samples:
   ```bash
   sqlite3 /var/lib/detector/quarantine.db \
     "DELETE FROM quarantine WHERE reviewed = 1;"
   sqlite3 /var/lib/detector/quarantine.db "VACUUM;"
   ```
2. If disk critically full, archive old entries:
   ```bash
   # Export entries older than 7 days
   sqlite3 /var/lib/detector/quarantine.db \
     ".mode json" \
     "SELECT * FROM quarantine WHERE quarantined_at < unixepoch() - 604800;" \
     > /backup/quarantine_archive_$(date +%Y%m%d).json
   
   # Delete archived entries
   sqlite3 /var/lib/detector/quarantine.db \
     "DELETE FROM quarantine WHERE quarantined_at < unixepoch() - 604800;"
   sqlite3 /var/lib/detector/quarantine.db "VACUUM;"
   ```

**Short-term (< 1 hour):**
1. Enable automatic retention policy:
   ```bash
   curl -X POST http://detector:8080/config \
     -d '{"quarantine_retention_days": 30, "auto_purge_reviewed": true}'
   ```
2. Expand volume if on Kubernetes:
   ```bash
   kubectl patch pvc quarantine-storage -p '{"spec":{"resources":{"requests":{"storage":"50Gi"}}}}'
   ```
3. If caused by FP spike: address root cause per Scenario 1 first.

**Long-term:**
- Implement tiered storage: hot (SQLite) → warm (S3/object store)
- Set up automated archival cron job
- Configure disk usage alerting at 60% (warning) and 80% (critical)
- Size storage based on: `ingestion_rate × FP_rate × retention_days × avg_sample_size`
- Consider storing only metadata + sample ID in SQLite, with full sample data in object storage

### Escalation
- If disk is 95%+ full and growing: page on-call immediately
- If large volume is from real poison campaign: escalate to security team
- If data loss occurred (writes failed): document gap in audit log and notify compliance

---

## General On-Call Notes

### Quick Health Check
```bash
# All-in-one status
curl http://detector:8080/health | jq .

# Expected output:
# {
#   "status": "healthy",
#   "kafka_connected": true,
#   "redis_connected": true,
#   "quarantine_db_ok": true,
#   "consumer_lag": 42,
#   "uptime_seconds": 86400
# }
```

### Key Metrics to Monitor
| Metric | Warning | Critical |
|--------|---------|----------|
| Consumer lag | > 10,000 | > 100,000 |
| FP rate | > 10% | > 30% |
| Quarantine disk | > 60% | > 80% |
| Detection latency P99 | > 100ms | > 500ms |
| Drift alert frequency | > 3/hour | > 10/hour |

### Contacts
- ML Platform Team: #ml-platform (Slack)
- Data Platform: #data-infra (Slack)
- Security: #security-ops (Slack), PagerDuty escalation policy "Security Incidents"

### Post-Incident
1. Update this runbook if a new scenario was encountered
2. File post-mortem within 48 hours for any Sev1/Sev2 incident
3. Track action items in the incident tracker
