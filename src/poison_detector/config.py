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

import logging
import os
from pathlib import Path
from typing import Any

_logger = logging.getLogger(__name__)

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

    model_config = {"env_prefix": "POISON_THRESHOLD_", "validate_assignment": True}

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

    model_config = {"env_prefix": "POISON_STREAM_", "validate_assignment": True}

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

    model_config = {"env_prefix": "POISON_FLAG_", "validate_assignment": True}

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

    model_config = {"env_prefix": "POISON_ALERT_", "validate_assignment": True}

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

    model_config = {"env_prefix": "POISON_", "validate_assignment": True}

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
        self._merge_section("thresholds", self.thresholds, data.get("thresholds"), "POISON_THRESHOLD_")
        self._merge_section("streaming", self.streaming, data.get("streaming"), "POISON_STREAM_")
        self._merge_section("features", self.features, data.get("features"), "POISON_FLAG_")
        self._merge_section("alerts", self.alerts, data.get("alerts"), "POISON_ALERT_")

        if "environment" in data and "POISON_ENVIRONMENT" not in os.environ:
            setattr(self, "environment", data["environment"])

    def _merge_section(
        self,
        section_name: str,
        target: BaseSettings,
        section: Any,
        env_prefix: str,
    ) -> None:
        """Merge one YAML section onto a sub-config.

        Env vars still win over YAML. Unknown keys are logged as warnings
        instead of being silently dropped (a common source of misconfiguration
        where a typo'd key leaves detection running on unexpected defaults).
        Values go through normal assignment so Pydantic validates/coerces them
        (``validate_assignment`` is enabled on the models) -- unlike the old
        ``object.__setattr__`` path, which bypassed validation entirely and
        could leave e.g. a string where a float was required.
        """
        if section is None:
            return
        if not isinstance(section, dict):
            _logger.warning(
                "Config section '%s' should be a mapping, got %s; ignoring.",
                section_name,
                type(section).__name__,
            )
            return

        for key, value in section.items():
            if not hasattr(target, key):
                _logger.warning(
                    "Ignoring unknown config key '%s.%s' (not a recognized setting).",
                    section_name,
                    key,
                )
                continue
            env_key = f"{env_prefix}{key.upper()}"
            if env_key in os.environ:
                continue
            setattr(target, key, value)

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
