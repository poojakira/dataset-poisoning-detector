"""Coverage tests for layered configuration loading.

Verifies DetectorConfig.from_yaml with a temp YAML file, that environment
variables take precedence over YAML defaults, and that _load_yaml_file handles
missing files and malformed YAML by degrading to defaults.
"""

import os

import pytest

from poison_detector.config import (
    DetectorConfig,
    _load_yaml_file,
)


@pytest.fixture(autouse=True)
def _clean_env():
    """Remove POISON_* env vars around each test to avoid cross-contamination."""
    saved = {k: v for k, v in os.environ.items() if k.startswith("POISON_")}
    for k in list(saved):
        del os.environ[k]
    yield
    for k in [k for k in os.environ if k.startswith("POISON_")]:
        del os.environ[k]
    os.environ.update(saved)


def test_from_yaml_applies_overrides(tmp_path):
    """from_yaml loads nested threshold/streaming/feature/alert values."""
    cfg_file = tmp_path / "realtime.yaml"
    cfg_file.write_text(
        "environment: prod\n"
        "thresholds:\n"
        "  zscore_threshold: 4.5\n"
        "  ensemble_vote_threshold: 3\n"
        "streaming:\n"
        "  window_size: 2048\n"
        "features:\n"
        "  enable_alerting: true\n"
        "alerts:\n"
        "  cooldown_seconds: 42\n"
    )
    config = DetectorConfig.from_yaml(str(cfg_file))

    assert config.environment == "prod"
    assert config.thresholds.zscore_threshold == 4.5
    assert config.thresholds.ensemble_vote_threshold == 3
    assert config.streaming.window_size == 2048
    assert config.features.enable_alerting is True
    assert config.alerts.cooldown_seconds == 42
    # from_yaml cleans up the env var it set
    assert "POISON_CONFIG_FILE" not in os.environ


def test_env_var_overrides_yaml(tmp_path):
    """An explicit env var wins over the YAML-provided default."""
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("thresholds:\n  zscore_threshold: 4.5\n")

    os.environ["POISON_THRESHOLD_ZSCORE_THRESHOLD"] = "9.0"
    config = DetectorConfig.from_yaml(str(cfg_file))
    # Env var (9.0) must take precedence over YAML (4.5)
    assert config.thresholds.zscore_threshold == 9.0


def test_load_yaml_missing_file_returns_none(tmp_path):
    """_load_yaml_file returns None for a nonexistent path."""
    assert _load_yaml_file(str(tmp_path / "does-not-exist.yaml")) is None


def test_load_yaml_bad_yaml_returns_none(tmp_path):
    """_load_yaml_file returns None for malformed YAML rather than raising."""
    bad = tmp_path / "bad.yaml"
    bad.write_text("this: : : not valid\n  - broken\n:::")
    assert _load_yaml_file(str(bad)) is None


def test_load_yaml_non_mapping_returns_none(tmp_path):
    """A YAML document that is not a mapping is treated as no config."""
    scalar = tmp_path / "scalar.yaml"
    scalar.write_text("- just\n- a\n- list\n")
    assert _load_yaml_file(str(scalar)) is None


def test_load_yaml_valid_mapping(tmp_path):
    """_load_yaml_file returns the parsed dict for a valid mapping."""
    good = tmp_path / "good.yaml"
    good.write_text("environment: staging\nthresholds:\n  iqr_multiplier: 2.0\n")
    data = _load_yaml_file(str(good))
    assert data["environment"] == "staging"
    assert data["thresholds"]["iqr_multiplier"] == 2.0


def test_config_defaults_without_yaml():
    """A bare DetectorConfig uses documented defaults."""
    config = DetectorConfig()
    assert config.environment == "dev"
    assert config.thresholds.zscore_threshold == 3.0
    assert config.features.enable_alerting is False
    assert config.streaming.refit_interval == 1000
