"""
Configuration management for the real-time poisoning detection system.

Loads settings from environment variables, YAML files, and defaults in a
layered fashion. Environment variables override YAML which overrides defaults.

Threat Model Assumptions:
    - Configuration values are trusted. They come from deployment infrastructure
      (env vars, config files on disk), NOT from user input or network requests.
    - An attacker who can modify the config file can disable detection entirely,
      so config files must be protected by filesystem permissions and deployment
      controls (e.g., sealed secrets, read-only containers).

Honest Limitations:
    - Threshold tuning is still an art. The defaults here are calibrated for
      typical tabular/embedding data but will need per-dataset adjustment.
    - YAML loading uses PyYAML safe_load to prevent arbitrary code execution,
      but cannot prevent all denial-of-service via deeply nested structures.
    - Feature flags provide kill switches but no gradual rollout (no percentage-
      based feature gates). For that, use an external feature flag service.

Security Notes:
    - NEVER load config from untrusted sources (user uploads, API params).
    - YAML is loaded with yaml.safe_load only -- no Loader= parameter.
    - No eval(), exec(), or dynamic import based on config values.
    - Sensitive values (API keys for alerting) should come from env vars,
      not YAML files committed to version control.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from pydantic_settings import BaseSettings
from pydantic import Field


class DetectionThresholds(BaseSettings):
    """Thresholds for anomaly scoring and flagging.

    These values control the sensitivity vs. specificity tradeoff.
    Lower thresholds catch more attacks but produce more false positives.
    """

    model_config = {"env_prefix": "POISON_THRESHOLD_"}

    zscore_threshold: float = Field(
        default=3.0,
        description="Z-score above which a sample is flagged. Standard: 3.0 (99.7%)",
    )
    iqr_multiplier: float = Field(
        default=1.5,
        description="IQR multiplier for fence calculation. Standard: 1.5 (mild outlier)",
    )
    isolation_contamination: float = Field(
        default=0.05,
        description="Expected poison rate for IsolationForest. Range: (0, 0.5]",
    )
    ensemble_vote_threshold: int = Field(
        default=2,
        description="Minimum method votes to flag a sample as poisoned",
    )
    similarity_threshold: float = Field(
        default=0.95,
        description="Cosine similarity above which samples are considered duplicates",
    )


class StreamingConfig(BaseSettings):
    """Configuration for the streaming detector component."""

    model_config = {"env_prefix": "POISON_STREAM_"}

    window_size: int = Field(
        default=10000,
        description="Rolling window size for online statistics",
    )
    refit_interval: int = Field(
        default=1000,
        description="Number of clean samples between IsolationForest refits",
    )
    drift_sensitivity: float = Field(
        default=0.01,
        description="ADWIN delta parameter. Lower = more sensitive to drift",
    )
    max_batch_size: int = Field(
        default=512,
        description="Maximum samples per batch scoring call",
    )


class FeatureFlags(BaseSettings):
    """Feature flags for enabling/disabling detection methods.

    Use these as kill switches when a method is misbehaving in production.
    """

    model_config = {"env_prefix": "POISON_FLAG_"}

    enable_zscore: bool = Field(default=True, description="Enable z-score detection")
    enable_iqr: bool = Field(default=True, description="Enable IQR detection")
    enable_isolation: bool = Field(
        default=True, description="Enable Isolation Forest detection"
    )
    enable_drift_detection: bool = Field(
        default=True, description="Enable concept drift detection"
    )
    enable_fingerprinting: bool = Field(
        default=True, description="Enable sample fingerprinting"
    )
    enable_alerting: bool = Field(
        default=False, description="Enable alert dispatch (off by default in dev)"
    )


class AlertConfig(BaseSettings):
    """Alert dispatch configuration."""

    model_config = {"env_prefix": "POISON_ALERT_"}

    slack_webhook_url: str = Field(default="", description="Slack webhook URL")
    pagerduty_routing_key: str = Field(
        default="", description="PagerDuty Events API routing key"
    )
    webhook_urls: list[str] = Field(
        default_factory=list, description="Custom webhook URLs for alert dispatch"
    )
    cooldown_seconds: int = Field(
        default=300, description="Minimum seconds between repeated alerts"
    )
    poison_rate_alert_threshold: float = Field(
        default=0.1,
        description="Poison rate above which to trigger an alert",
    )


class DetectorConfig(BaseSettings):
    """Root configuration for the dataset poisoning detector.

    Loads configuration in the following precedence order:
    1. Environment variables (highest priority)
    2. YAML config file (if specified via POISON_CONFIG_FILE env var)
    3. Defaults (lowest priority)

    Usage:
        config = DetectorConfig()  # loads from env + yaml
        config = DetectorConfig.from_yaml("config/realtime.yaml")
    """

    model_config = {"env_prefix": "POISON_"}

    environment: str = Field(
        default="dev",
        description="Deployment environment: dev, staging, or prod",
    )
    config_file: str = Field(
        default="",
        description="Path to YAML config file. Set via POISON_CONFIG_FILE env var.",
    )

    thresholds: DetectionThresholds = Field(default_factory=DetectionThresholds)
    streaming: StreamingConfig = Field(default_factory=StreamingConfig)
    features: FeatureFlags = Field(default_factory=FeatureFlags)
    alerts: AlertConfig = Field(default_factory=AlertConfig)

    def model_post_init(self, __context: Any) -> None:
        """Load YAML config file if specified, merging with env var overrides."""
        config_path = self.config_file or os.environ.get("POISON_CONFIG_FILE", "")
        if config_path:
            yaml_data = _load_yaml_file(config_path)
            if yaml_data:
                self._apply_yaml_overrides(yaml_data)

    def _apply_yaml_overrides(self, data: dict[str, Any]) -> None:
        """Apply YAML values as defaults (env vars still take precedence)."""
        if "thresholds" in data and isinstance(data["thresholds"], dict):
            for key, value in data["thresholds"].items():
                if hasattr(self.thresholds, key):
                    # Only set if env var was not explicitly set
                    env_key = f"POISON_THRESHOLD_{key.upper()}"
                    if env_key not in os.environ:
                        object.__setattr__(self.thresholds, key, value)

        if "streaming" in data and isinstance(data["streaming"], dict):
            for key, value in data["streaming"].items():
                if hasattr(self.streaming, key):
                    env_key = f"POISON_STREAM_{key.upper()}"
                    if env_key not in os.environ:
                        object.__setattr__(self.streaming, key, value)

        if "features" in data and isinstance(data["features"], dict):
            for key, value in data["features"].items():
                if hasattr(self.features, key):
                    env_key = f"POISON_FLAG_{key.upper()}"
                    if env_key not in os.environ:
                        object.__setattr__(self.features, key, value)

        if "alerts" in data and isinstance(data["alerts"], dict):
            for key, value in data["alerts"].items():
                if hasattr(self.alerts, key):
                    env_key = f"POISON_ALERT_{key.upper()}"
                    if env_key not in os.environ:
                        object.__setattr__(self.alerts, key, value)

        if "environment" in data:
            env_key = "POISON_ENVIRONMENT"
            if env_key not in os.environ:
                object.__setattr__(self, "environment", data["environment"])

    @classmethod
    def from_yaml(cls, path: str | Path) -> DetectorConfig:
        """Create a config instance from a YAML file.

        Args:
            path: Path to the YAML configuration file.

        Returns:
            DetectorConfig instance with YAML values as defaults.
        """
        os.environ["POISON_CONFIG_FILE"] = str(path)
        try:
            return cls()
        finally:
            del os.environ["POISON_CONFIG_FILE"]


def _load_yaml_file(path: str | Path) -> dict[str, Any] | None:
    """Safely load a YAML file, returning None on failure.

    Uses yaml.safe_load to prevent arbitrary code execution.
    Returns None (not raises) on missing file or parse error to allow
    graceful degradation to defaults.
    """
    if not _YAML_AVAILABLE:
        return None

    path = Path(path)
    if not path.exists():
        return None

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            return data
        return None
    except (yaml.YAMLError, OSError):
        return None
