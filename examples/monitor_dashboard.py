"""
Terminal Dashboard for Real-Time Poisoning Detection Metrics

Displays live metrics from the detection system in a simple terminal UI.
Refreshes every second showing throughput, latency, detection rates, and
drift status.

Usage:
    python examples/monitor_dashboard.py

    # Or with a custom refresh interval
    python examples/monitor_dashboard.py --interval 2.0

Requirements:
    pip install -e ".[realtime]"

This is intentionally a lightweight terminal dashboard -- no curses dependency,
no external UI library. For production monitoring, use the Grafana dashboards
included in docker-compose.yml.
"""

import argparse
import os
import sys
import time

from poison_detector.stream import StreamingDetector
from poison_detector.drift import ConceptDriftDetector
from poison_detector.fingerprint import SampleFingerprinter
from poison_detector.metrics import (
    SAMPLES_PROCESSED,
    SAMPLES_POISONED,
    SCORING_LATENCY,
    DRIFT_SCORE,
    QUEUE_DEPTH,
    BASELINE_SIZE,
)


def clear_screen() -> None:
    """Clear terminal screen cross-platform."""
    os.system("cls" if os.name == "nt" else "clear")


def format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"


class MetricsDashboard:
    """
    Simple terminal dashboard for monitoring detection metrics.

    Reads from Prometheus metric objects in-process. For remote monitoring,
    scrape the /metrics endpoint exposed by the API service.
    """

    def __init__(self, refresh_interval: float = 1.0) -> None:
        self.refresh_interval = refresh_interval
        self.start_time = time.time()
        self._prev_processed = 0.0
        self._prev_poisoned = 0.0
        self._prev_time = time.time()

    def _get_counter_value(self, counter) -> float:
        """Extract current value from a Prometheus counter."""
        # prometheus_client stores value in _value for counters
        try:
            return counter._value.get()
        except AttributeError:
            return 0.0

    def _get_gauge_value(self, gauge) -> float:
        """Extract current value from a Prometheus gauge."""
        try:
            return gauge._value.get()
        except AttributeError:
            return 0.0

    def _get_histogram_stats(self, histogram) -> dict:
        """Extract stats from a Prometheus histogram."""
        try:
            return {
                "count": histogram._count.get(),
                "sum": histogram._sum.get(),
            }
        except AttributeError:
            return {"count": 0, "sum": 0.0}

    def render(self) -> str:
        """Render the dashboard as a string."""
        now = time.time()
        uptime = now - self.start_time
        dt = now - self._prev_time

        # Current metric values
        processed = self._get_counter_value(SAMPLES_PROCESSED)
        poisoned = self._get_counter_value(SAMPLES_POISONED)
        drift_score = self._get_gauge_value(DRIFT_SCORE)
        queue_depth = self._get_gauge_value(QUEUE_DEPTH)
        baseline_size = self._get_gauge_value(BASELINE_SIZE)
        latency_stats = self._get_histogram_stats(SCORING_LATENCY)

        # Calculate rates
        rate_processed = (processed - self._prev_processed) / max(dt, 0.001)
        rate_poisoned = (poisoned - self._prev_poisoned) / max(dt, 0.001)
        poison_pct = (poisoned / max(processed, 1)) * 100
        avg_latency_ms = (
            (latency_stats["sum"] / max(latency_stats["count"], 1)) * 1000
        )

        self._prev_processed = processed
        self._prev_poisoned = poisoned
        self._prev_time = now

        lines = [
            "",
            "  ┌─────────────────────────────────────────────────────────┐",
            "  │       DATASET POISONING DETECTOR - LIVE METRICS         │",
            "  └─────────────────────────────────────────────────────────┘",
            "",
            f"   Uptime: {format_duration(uptime)}",
            "",
            "  ┌─── THROUGHPUT ──────────────────────────────────────────┐",
            f"  │  Samples processed:  {processed:>12,.0f}                      │",
            f"  │  Processing rate:    {rate_processed:>12,.1f} samples/sec         │",
            f"  │  Queue depth:        {queue_depth:>12,.0f}                      │",
            f"  │  Baseline size:      {baseline_size:>12,.0f}                      │",
            "  └─────────────────────────────────────────────────────────┘",
            "",
            "  ┌─── DETECTION ───────────────────────────────────────────┐",
            f"  │  Samples poisoned:   {poisoned:>12,.0f}                      │",
            f"  │  Poison rate:        {poison_pct:>11.2f}%                      │",
            f"  │  Detection rate:     {rate_poisoned:>12,.1f} flags/sec           │",
            f"  │  Drift score:        {drift_score:>12.4f}                      │",
            "  └─────────────────────────────────────────────────────────┘",
            "",
            "  ┌─── LATENCY ─────────────────────────────────────────────┐",
            f"  │  Avg scoring time:   {avg_latency_ms:>10.2f} ms                   │",
            f"  │  Total scored:       {latency_stats['count']:>12,.0f}                      │",
            "  └─────────────────────────────────────────────────────────┘",
            "",
            "  Press Ctrl+C to exit",
            "",
        ]
        return "\n".join(lines)

    def run(self) -> None:
        """Run the dashboard in a loop."""
        print("\n  Starting metrics dashboard...")
        print("  (In production, metrics are scraped by Prometheus at /metrics)")
        print("  (This dashboard reads in-process metrics for demo purposes)\n")
        time.sleep(1)

        try:
            while True:
                clear_screen()
                print(self.render())
                time.sleep(self.refresh_interval)
        except KeyboardInterrupt:
            print("\n  Dashboard stopped.")


def main() -> None:
    """Entry point for the monitoring dashboard."""
    parser = argparse.ArgumentParser(
        description="Terminal dashboard for poisoning detection metrics"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Refresh interval in seconds (default: 1.0)",
    )
    args = parser.parse_args()
    dashboard = MetricsDashboard(refresh_interval=args.interval)
    dashboard.run()


if __name__ == "__main__":
    main()
