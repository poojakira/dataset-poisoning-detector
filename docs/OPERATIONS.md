# Operations Runbook

## Scaling

### Horizontal Scaling (HPA)

The Horizontal Pod Autoscaler is configured to scale based on CPU utilization and
scoring latency:

| Metric | Target | Scale Up | Scale Down |
|--------|--------|----------|------------|
| CPU Utilization | 70% average | +2 pods or +50% (max) per 60s | -1 pod per 60s |
| Scoring Latency | 500ms average | Same as CPU triggers | Same as CPU triggers |

**Configuration** (from `k8s/hpa.yaml`):
- Minimum replicas: 3
- Maximum replicas: 20
- Scale-up stabilization: 30 seconds
- Scale-down stabilization: 300 seconds (prevents flapping)

**Manual scaling for expected load**:

```bash
# Scale up before a known high-load event
kubectl scale deployment/poison-detector -n poison-detector --replicas=10

# Return to HPA-managed scaling afterward
kubectl annotate hpa poison-detector -n poison-detector \
  autoscaling.alpha.kubernetes.io/last-scale-event-
```

**Monitoring scaling decisions**:

```bash
# View HPA status and events
kubectl describe hpa poison-detector -n poison-detector

# View scaling events
kubectl get events -n poison-detector --field-selector reason=SuccessfulRescale
```

### Vertical Scaling (Resource Tuning)

Default resource configuration:

| Resource | Request | Limit | Rationale |
|----------|---------|-------|-----------|
| CPU | 500m | 2000m | IsolationForest refit is CPU-intensive |
| Memory | 512Mi | 2Gi | Rolling window of 10K samples + sklearn model |

**When to adjust**:
- If OOM kills occur: increase memory limit (check `kubectl describe pod` for OOMKilled status)
- If scoring latency exceeds SLO: increase CPU limit or add replicas
- If IsolationForest refit causes latency spikes: increase CPU request for guaranteed resources

**Tuning procedure**:

```bash
# Check current resource usage
kubectl top pods -n poison-detector

# Update resource limits
kubectl set resources deployment/poison-detector -n poison-detector \
  --limits=cpu=4000m,memory=4Gi \
  --requests=cpu=1000m,memory=1Gi
```

---

## Backups

### RDS Automated Snapshots

| Configuration | Value |
|--------------|-------|
| Backup window | 03:00-04:00 UTC (daily) |
| Retention period | 35 days |
| Multi-AZ replication | Enabled |
| Encryption | AES-256 via KMS |

**Manual snapshot before major changes**:

```bash
aws rds create-db-snapshot \
  --db-instance-identifier poison-detector-db \
  --db-snapshot-identifier "pre-migration-$(date +%Y%m%d-%H%M%S)"
```

**Restore from snapshot**:

```bash
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier poison-detector-db-restored \
  --db-snapshot-identifier <snapshot-id> \
  --db-instance-class db.r6g.large
```

### Audit Log Archival

Audit logs follow a tiered storage lifecycle:

| Age | Storage Tier | Action |
|-----|-------------|--------|
| 0-30 days | Local EBS / PV | Active, queryable |
| 30 days | S3 Standard | Archived via CronJob |
| 1 year | S3 Infrequent Access | Lifecycle transition |
| 3 years | S3 Glacier | Lifecycle transition |
| 7 years | S3 Glacier Deep Archive | Final retention |
| 7+ years | Deleted | Lifecycle expiration |

**Archival CronJob** (runs daily):

```bash
# Rotate and upload audit logs
kubectl exec -n poison-detector deployment/poison-detector -- \
  python -m poison_detector.audit_archiver \
  --older-than 30d \
  --destination s3://poison-detector-audit-prod/archive/
```

**Integrity verification after archival**:

```bash
# Verify chain integrity of archived segment
python -m poison_detector.audit verify \
  --file s3://poison-detector-audit-prod/archive/2024-01/audit_trail.jsonl
```

### Quarantine Data Backup

Quarantined samples are backed up with the RDS database. Additional considerations:

- Quarantine data is encrypted at rest (AES-256-GCM envelope encryption)
- Quarterly export to S3 for long-term analysis
- Retention follows data classification policy (default: 1 year after resolution)

---

## Incident Response

### Severity Definitions

| Severity | Definition | Examples | Response Time |
|----------|-----------|----------|---------------|
| P1 - Critical | Service down, data integrity compromised, active security breach | Audit chain broken, all replicas down, auth bypass detected | 15 minutes |
| P2 - High | Significant degradation, SLO breach imminent, potential security issue | >50% error rate, latency 10x baseline, anomalous auth failures | 30 minutes |
| P3 - Medium | Minor degradation, single component failure, non-critical alert | One replica down, circuit breaker open, rate limit approaching | 4 hours |
| P4 - Low | Cosmetic issue, non-urgent maintenance needed, informational | Key rotation overdue, disk usage warning, minor metric anomaly | 24 hours |

### Escalation Matrix

| Time Elapsed | P1 | P2 | P3 | P4 |
|-------------|-----|-----|-----|-----|
| 0 min | On-call engineer + Eng Manager | On-call engineer | On-call engineer | Ticket created |
| 15 min | + VP Engineering | + Eng Manager | - | - |
| 30 min | + CISO (if security) | + VP Engineering | - | - |
| 60 min | + CTO | + CISO (if security) | + Eng Manager | - |
| 4 hours | Executive briefing | Status update to stakeholders | - | - |

### Communication Templates

**P1 Initial Notification**:

```
Subject: [P1] Dataset Poisoning Detector - [Brief Description]

Status: INVESTIGATING
Impact: [Description of user/service impact]
Started: [UTC timestamp]
Incident Commander: [Name]

What we know:
- [Symptom 1]
- [Symptom 2]

Actions in progress:
- [Action 1]
- [Action 2]

Next update in: 15 minutes
```

**Status Update**:

```
Subject: [P1] UPDATE - Dataset Poisoning Detector - [Brief Description]

Status: [INVESTIGATING | IDENTIFIED | MONITORING | RESOLVED]
Impact: [Updated impact assessment]
Duration: [Time since start]

Progress since last update:
- [What was done]
- [What was found]

Current actions:
- [What is being done now]

Next update in: [Time]
```

**Resolution Notification**:

```
Subject: [P1] RESOLVED - Dataset Poisoning Detector - [Brief Description]

Status: RESOLVED
Duration: [Total incident duration]
Impact: [Final impact summary]
Root Cause: [Brief root cause]

Timeline:
- [Time]: [Event]
- [Time]: [Event]

Follow-up:
- Postmortem scheduled for [date]
- Tracking items: [JIRA tickets]
```

### Incident Response Procedures

**Auth Bypass Detected (P1)**:
1. Rotate all API keys immediately
2. Revoke and reissue JWT signing keys via IdP
3. Review audit log for unauthorized access patterns
4. Block suspicious source IPs at the network level
5. Verify audit chain integrity

**Audit Chain Integrity Failure (P1)**:
1. Immediately isolate the affected pod(s)
2. Preserve the corrupted log file as forensic evidence
3. Compare against remote backup (S3) to identify modifications
4. Restore from last known-good backup
5. Review file access logs for unauthorized modifications
6. Engage security team for forensic investigation

**High Poison Rate Alert (P2)**:
1. Check if the elevated rate correlates with a new data source
2. Review quarantined samples for patterns (coordinated attack vs. data quality issue)
3. If attack: block the source, escalate to security
4. If data quality: notify the data team, adjust thresholds if needed
5. Monitor for return to baseline

**Circuit Breaker Open (P3)**:
1. Identify which downstream dependency triggered the breaker
2. Check Redis/PostgreSQL/external service health
3. If dependency is recovering: wait for half-open recovery
4. If dependency is down: engage the responsible team
5. Monitor degraded scoring quality during open state

---

## Maintenance Windows

### Zero-Downtime Deployments

The system uses Kubernetes rolling updates with the following configuration:

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 25%
    maxUnavailable: 0
```

**Deployment procedure**:

```bash
# Update container image
kubectl set image deployment/poison-detector \
  poison-detector=<ecr-url>:new-tag \
  -n poison-detector

# Monitor rollout
kubectl rollout status deployment/poison-detector -n poison-detector

# Verify health after rollout
curl -s http://poison-detector.internal/health | jq .status
```

**Pod Disruption Budget** ensures minimum availability during node maintenance:
- Minimum available: 2 pods (from `k8s/pdb.yaml`)
- Prevents draining all pods simultaneously during node upgrades

### Database Migrations

**Pre-migration checklist**:
1. Create manual RDS snapshot
2. Test migration on staging environment
3. Verify migration is backward-compatible (old code works with new schema)
4. Schedule during low-traffic period

**Migration procedure**:

```bash
# 1. Create backup
aws rds create-db-snapshot \
  --db-instance-identifier poison-detector-db \
  --db-snapshot-identifier "pre-migration-$(date +%Y%m%d)"

# 2. Run migration (assumes alembic or similar)
kubectl exec -n poison-detector deployment/poison-detector -- \
  python -m alembic upgrade head

# 3. Verify
kubectl exec -n poison-detector deployment/poison-detector -- \
  python -m alembic current

# 4. Monitor for errors in application logs
kubectl logs -l app=poison-detector -n poison-detector --since=5m | grep -i error
```

### Baseline Refresh

The IsolationForest baseline should be refreshed when:
- Legitimate data distribution changes (new features, new data sources)
- After a confirmed poisoning incident (window may be contaminated)
- Periodically (recommended: monthly) to adapt to gradual drift

**Refresh procedure**:

```bash
# 1. Export known-clean samples from the data warehouse
python scripts/export_clean_baseline.py \
  --source warehouse \
  --output /tmp/clean_baseline.parquet \
  --samples 50000

# 2. Upload baseline update
curl -X POST http://poison-detector.internal/admin/baseline/refresh \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -F "data=@/tmp/clean_baseline.parquet"

# 3. Monitor detection metrics for 1 hour after refresh
# - Watch for sudden spike in false positives
# - Verify poison_rate returns to expected baseline
```

---

## Monitoring

### Key Metrics to Watch

| Metric | Normal Range | Warning Threshold | Critical Threshold |
|--------|-------------|-------------------|-------------------|
| `poison_detector_scoring_latency_seconds` p99 | <50ms | >100ms | >500ms |
| `poison_detector_samples_total` rate | Varies by deployment | <10% of expected | <1% of expected |
| `poison_detector_poison_rate` | <5% | >10% | >20% |
| `poison_detector_error_total` rate | <0.1% | >1% | >5% |
| Pod CPU usage | 30-60% | >70% | >90% |
| Pod memory usage | 40-60% | >80% | >90% |
| Redis connection count | <100 | >200 | >500 |
| RDS connections | <50 | >80% max | >95% max |

### Dashboard Usage

The Grafana dashboard (`observability/grafana-dashboard.json`) provides:

1. **Overview Panel**: Request rate, error rate, latency percentiles
2. **Detection Panel**: Poison rate over time, method vote distribution, drift status
3. **Infrastructure Panel**: CPU/memory per pod, HPA state, Redis/RDS metrics
4. **Audit Panel**: Auth success/failure rates, rate limit triggers, circuit breaker state

**Access**: `https://grafana.internal/d/poison-detector/overview`

### Alert Routing

| Alert | Severity | Channel | Runbook |
|-------|----------|---------|---------|
| HighPoisonRate | Warning | Slack #security-alerts | `observability/runbooks/high-poison-rate.md` |
| ScoringLatencyDegraded | Warning | Slack #platform-alerts | `observability/runbooks/latency-degradation.md` |
| ConceptDriftDetected | Info | Slack #ml-team | `observability/runbooks/drift-alert.md` |
| CircuitBreakerOpen | Warning | PagerDuty (P3) | See "Circuit Breaker Open" above |
| AuditChainBroken | Critical | PagerDuty (P1) + Slack | See "Audit Chain Integrity Failure" above |
| PodOOMKilled | Warning | Slack #platform-alerts | Increase memory limits |
| HPAMaxReplicas | Warning | Slack #platform-alerts | Review load, consider max increase |
| RateLimitExhausted | Info | Slack #security-alerts | Review client for abuse |

### Log Analysis

**Structured logging format** (JSON):

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "WARNING",
  "module": "rbac",
  "message": "RBAC DENY: identity=unknown-service permission=modify_config",
  "identity": "unknown-service",
  "permission": "modify_config",
  "trace_id": "abc123"
}
```

**Common log queries**:

```bash
# Find auth failures in the last hour
kubectl logs -l app=poison-detector -n poison-detector --since=1h | \
  grep "AUTH denied"

# Find circuit breaker transitions
kubectl logs -l app=poison-detector -n poison-detector --since=24h | \
  grep "circuit_breaker"

# Count poison detections per source
kubectl logs -l app=poison-detector -n poison-detector --since=1h | \
  grep "poison_detected" | jq -r '.source' | sort | uniq -c | sort -rn
```
