# Service Level Agreement (SLA)

## Overview

This document defines the Service Level Indicators (SLIs), Service Level Objectives (SLOs),
and operational commitments for the Dataset Poisoning Detector service.

---

## Service Level Indicators (SLIs)

SLIs are the quantitative measurements of service health.

### Availability

**Definition**: The proportion of valid requests that are successfully served (non-5xx responses)
over a calendar month.

```
Availability = (total_requests - 5xx_responses) / total_requests * 100%
```

**Measurement**: Calculated from the ingress controller access logs and Prometheus
`http_requests_total` metric, excluding health checks and metrics scrapes.

### Latency

**Definition**: The time between receiving a valid request and sending the complete response,
measured at the application boundary (excludes network transit time).

```
Latency (p99) = 99th percentile of poison_detector_scoring_latency_seconds
```

**Measurement**: Prometheus histogram `poison_detector_scoring_latency_seconds`, sampled
every 15 seconds, aggregated over 5-minute windows.

### Throughput

**Definition**: The sustained rate of samples the system can process while maintaining
latency SLO.

```
Throughput = samples_processed_total rate over 1-minute window
```

**Measurement**: Prometheus counter `poison_detector_samples_total` rate.

### Error Rate

**Definition**: The proportion of requests resulting in an error response (4xx client errors
excluded, 5xx server errors included).

```
Error Rate = 5xx_responses / total_requests * 100%
```

**Measurement**: HTTP response code distribution from ingress metrics.

---

## Service Level Objectives (SLOs)

| SLI | Target | Measurement Window | Burn Rate Alert |
|-----|--------|-------------------|-----------------|
| Availability | 99.95% | 30-day rolling | 14.4x (1h), 6x (6h) |
| Latency (p99) | < 50ms | 5-minute window | > 100ms for 5 min |
| Throughput | 10,000 samples/sec | Per-replica steady state | < 5,000 samples/sec |
| Error Rate | < 0.1% | 30-day rolling | > 1% for 5 min |

### Availability Target: 99.95%

This allows for:
- 21.9 minutes of downtime per month
- 4.38 hours of downtime per year

**What counts as downtime**:
- HTTP 5xx responses from the /score or /batch endpoints
- Health check returning "unhealthy" status
- Connection refused or timeout (>30s) on any endpoint

**What does NOT count as downtime**:
- Scheduled maintenance windows (with 72h advance notice)
- 429 rate limit responses (functioning as designed)
- Client errors (4xx responses to malformed requests)
- Degraded mode (statistical-only scoring when circuit breaker is open)

### Latency Target: < 50ms p99

| Percentile | Target | Typical |
|-----------|--------|---------|
| p50 | < 5ms | 2-4ms |
| p90 | < 20ms | 8-15ms |
| p95 | < 35ms | 15-25ms |
| p99 | < 50ms | 20-40ms |
| p99.9 | < 200ms | 50-150ms (during refit) |

**Notes**:
- IsolationForest refit can cause periodic latency spikes at p99.9
- Statistical-only scoring (degraded mode) is typically < 5ms p99
- Batch endpoint latency scales linearly with batch size

### Throughput Target: 10,000 samples/sec

Measured per deployment (all replicas combined):
- Single replica: approximately 2,000-3,000 samples/sec
- Minimum deployment (3 replicas): approximately 6,000-9,000 samples/sec
- Full scale (20 replicas): approximately 40,000-60,000 samples/sec

### Error Rate Target: < 0.1%

- Maximum 1 error per 1,000 requests over a 30-day window
- Transient errors (circuit breaker recovery, Redis reconnection) are included
- Must be below 0.1% as a monthly average

---

## Error Budget Policy

### Error Budget Calculation

```
Monthly error budget = 1 - SLO target
                     = 1 - 0.9995
                     = 0.05% of requests may fail

For 1M requests/month:
  Error budget = 500 allowed errors
```

### Budget Consumption States

| Budget Remaining | State | Actions |
|-----------------|-------|---------|
| > 50% | Normal | Feature development proceeds normally |
| 25% - 50% | Caution | Prioritize reliability work, reduce risky changes |
| 10% - 25% | At Risk | Freeze non-critical deployments, focus on stability |
| < 10% | Exhausted | Stop all feature work, reliability-only changes |
| 0% | Breached | Incident review required, stakeholder notification |

### What Happens When Budget Is Consumed

1. **Deployment freeze**: No new feature deployments until budget recovers above 25%
2. **Postmortem required**: Every incident consuming >10% of the budget requires a postmortem
3. **Reliability sprint**: Engineering shifts to 100% reliability work until budget > 50%
4. **Stakeholder notification**: Monthly SLA report includes budget status and recovery plan
5. **Escalation**: If budget is breached for 2 consecutive months, executive review

### Budget Recovery

The error budget resets on a 30-day rolling basis. Historical errors fall out of the
window naturally. Proactive measures to accelerate recovery:
- Deploy fixes for known reliability issues
- Add capacity (scale up replicas)
- Improve circuit breaker recovery time
- Enhance input validation to reject more bad requests earlier

---

## Incident Severity Definitions

| Severity | User Impact | Error Budget Impact | Example |
|----------|-------------|-------------------|---------|
| P1 | Complete service outage | >50% budget in <1h | All replicas down, database unreachable |
| P2 | Major degradation | 10-50% budget in <4h | >50% error rate, latency 10x target |
| P3 | Minor degradation | 1-10% budget in <24h | Single replica failing, elevated errors |
| P4 | Minimal impact | <1% budget | Intermittent timeouts, one unhealthy pod |

---

## Support Tiers

| Tier | Availability | Response Time (P1) | Response Time (P2) | Escalation Path |
|------|-------------|-------------------|-------------------|-----------------|
| Standard | Business hours (9-5 PT, M-F) | 4 hours | 8 hours | Email only |
| Premium | Extended (6-22 PT, M-F) | 1 hour | 4 hours | Email + Slack |
| Enterprise | 24/7/365 | 15 minutes | 30 minutes | PagerDuty + Phone |

### Response Time vs. Resolution Time

- **Response time**: Time until an engineer acknowledges and begins investigating
- **Resolution time**: Time until the issue is resolved or a workaround is in place

| Severity | Target Resolution Time |
|----------|----------------------|
| P1 | 4 hours |
| P2 | 8 hours |
| P3 | 48 hours |
| P4 | 5 business days |

---

## Exclusions

The following are explicitly excluded from SLA calculations:

### Scheduled Maintenance

- Advance notice: minimum 72 hours for production changes
- Maintenance windows: Sundays 02:00-06:00 UTC (preferred)
- Duration: maximum 4 hours per window
- Frequency: no more than 2 scheduled windows per month
- Zero-downtime deployments do not count as maintenance windows

### Force Majeure

- Natural disasters affecting cloud provider regions
- Government actions or regulatory orders
- Internet backbone failures beyond provider control
- DDoS attacks exceeding 10x normal traffic (despite mitigation efforts)
- Cloud provider outages (AWS, GCP, Azure region failures)

### Customer-Caused Issues

- Requests exceeding documented rate limits (429 responses)
- Malformed requests failing input validation (400/422 responses)
- Unauthorized requests (401/403 responses)
- Customer-side network issues preventing connectivity
- Usage exceeding contracted capacity without prior arrangement

### Dependencies

- Third-party identity provider outages (affecting JWT issuance, not validation)
- Notification channel failures (Slack, PagerDuty outages)
- Customer-managed infrastructure issues (VPN, DNS, firewall)

---

## Reporting and Review

### Monthly SLA Report

Delivered to stakeholders by the 5th business day of each month:

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Availability | 99.95% | 99.97% | Met |
| Latency p99 | <50ms | 38ms | Met |
| Throughput | 10K/s | 12.4K/s | Met |
| Error rate | <0.1% | 0.03% | Met |
| Error budget remaining | >0% | 72% | Healthy |

### Quarterly Review

- SLO appropriateness assessment (are targets too loose or too tight?)
- Error budget trend analysis
- Capacity planning for next quarter
- Incident postmortem summary and recurring themes
- Reliability investment recommendations

---

## SLO Implementation

### Prometheus Recording Rules

```yaml
# Availability (success rate over 30 days)
- record: slo:availability:ratio_30d
  expr: |
    1 - (
      sum(rate(http_requests_total{status=~"5.."}[30d]))
      /
      sum(rate(http_requests_total[30d]))
    )

# Latency p99 over 5 minutes
- record: slo:latency:p99_5m
  expr: |
    histogram_quantile(0.99,
      rate(poison_detector_scoring_latency_seconds_bucket[5m])
    )

# Error budget remaining
- record: slo:error_budget:remaining
  expr: |
    1 - (
      (1 - slo:availability:ratio_30d) / (1 - 0.9995)
    )
```

### Alerting on Burn Rate

```yaml
# Fast burn: will exhaust budget in <1 hour
- alert: SLOBudgetBurnHigh
  expr: slo:error_budget:burn_rate_1h > 14.4
  for: 2m
  labels:
    severity: critical

# Slow burn: will exhaust budget in <3 days
- alert: SLOBudgetBurnMedium
  expr: slo:error_budget:burn_rate_6h > 6
  for: 15m
  labels:
    severity: warning
```
