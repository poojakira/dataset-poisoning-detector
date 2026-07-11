# Runbook: Latency Degradation Alert

## Alert

**Name:** LatencyDegraded  
**Severity:** Warning  
**Condition:** Scoring latency p99 exceeds 200ms for 5+ minutes

**Related Alert:**  
**Name:** RefitLatencyHigh  
**Severity:** Warning  
**Condition:** IsolationForest refit p99 exceeds 30s for 1+ minute

## Symptoms

- The `LatencyDegraded` alert fires
- Grafana "Scoring Latency Percentiles" panel shows p99 above 200ms
- API consumers report slow response times from `/score` endpoint
- Queue depth may be increasing as processing cannot keep up with inflow

## Diagnosis Steps

1. **Check IsolationForest refit timing:**
   ```bash
   # Check if a refit is currently in progress
   kubectl exec -it deploy/poison-detector -- \
     python -c "from poison_detector.metrics import REFIT_LATENCY; print('Check refit histogram')"
   ```
   - Refit operations block scoring during execution
   - If `RefitLatencyHigh` is also firing, the refit is the likely cause

2. **Check window size:**
   - Examine `poison_detector_baseline_size` metric
   - A large baseline window causes slower scoring (IsolationForest scales with sample count)
   - Check if baseline has grown beyond expected bounds

3. **Check resource utilization:**
   ```bash
   # CPU and memory for the detector pods
   kubectl top pods -l app=poison-detector
   
   # Check for throttling
   kubectl describe pod -l app=poison-detector | grep -A5 "State:"
   ```
   - CPU throttling is the most common cause of latency spikes
   - Memory pressure can trigger GC pauses

4. **Check feature dimensionality:**
   - If new features were added to the scoring pipeline, dimensionality increase causes latency
   - Review recent config changes to `feature_columns` or `n_features`

5. **Check concurrent load:**
   - Examine `rate(poison_detector_samples_processed_total[5m])`
   - If throughput spiked, latency may degrade under load

## Possible Causes

| Cause | Likelihood | Indicators |
|-------|-----------|------------|
| Large window triggering refit | High | Refit latency also elevated, periodic spikes |
| High dimensionality | Medium | Recent config change, consistent (not spiking) latency |
| Resource contention | High | CPU throttling, memory pressure, noisy neighbors |
| GC pressure | Medium | Sawtooth memory pattern, spiky latency |
| Increased traffic volume | Medium | Throughput metric shows spike, queue growing |
| Python GIL contention | Low | Multiple async handlers competing for CPU-bound scoring |

## Remediation Actions

### Immediate (within 5 minutes)

1. **Check if refit is the cause** - if `RefitLatencyHigh` is also firing, wait for refit to complete
2. **Check resource limits** - verify pods are not being throttled

### Short-term fixes

1. **Scale horizontally:**
   ```bash
   kubectl scale deployment poison-detector --replicas=4
   ```
   - Distributes load across more instances
   - Each instance handles fewer concurrent scoring requests

2. **Reduce window_size:**
   ```yaml
   # In detector config
   window_size: 500  # was 1000
   ```
   - Smaller baseline means faster IsolationForest inference
   - Trade-off: less historical context for drift detection

3. **Reduce refit_interval:**
   ```yaml
   # In detector config  
   refit_interval: 200  # was 100 (refit less frequently)
   ```
   - Less frequent refits mean fewer blocking operations
   - Trade-off: slower adaptation to legitimate distribution changes

4. **Increase CPU limits:**
   ```yaml
   resources:
     limits:
       cpu: "2000m"    # was 1000m
       memory: "2Gi"   # was 1Gi
   ```

### Long-term fixes

1. **Enable async refit** - move refit to background thread/process so it does not block scoring
2. **Implement model caching** - cache IsolationForest predictions for similar feature vectors
3. **Reduce feature dimensionality** - use PCA or feature selection to reduce scoring cost
4. **Implement request batching** - batch incoming samples to amortize IsolationForest overhead

## Escalation Path

| Time Elapsed | Action |
|-------------|--------|
| 0-5 min | On-call engineer investigates using this runbook |
| 5-15 min | If not resolved by scaling, engage platform team |
| 15-30 min | If latency impacts SLA, escalate to team lead |
| 30+ min | Consider temporarily increasing latency alert threshold |

## Performance Baselines

| Metric | Normal | Warning | Critical |
|--------|--------|---------|----------|
| p50 latency | < 10ms | 10-50ms | > 50ms |
| p95 latency | < 50ms | 50-150ms | > 150ms |
| p99 latency | < 100ms | 100-200ms | > 200ms |
| Refit latency | < 5s | 5-30s | > 30s |

## Related Alerts

- **RefitLatencyHigh** - often fires together; refit blocking is common cause
- **QueueBacklog** - fires when latency prevents timely processing
- **DetectorDown** - may fire if latency causes health check timeouts

## Contact

- ML Platform Team: #ml-platform-oncall
- Infrastructure Team: #infra-oncall
