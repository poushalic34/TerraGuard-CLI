from pathlib import Path

import pytest

from terraguard.config import TerraGuardConfig, apply_overrides, load_config
from terraguard.exceptions import ConfigError


def test_load_config_defaults_when_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = load_config()

    assert config.policy_packs == ("aws-foundation", "aws-eks")
    assert config.fail_on == "high"
    assert config.output_format == "console"


def test_load_config_from_file(tmp_path: Path) -> None:
    path = tmp_path / ".terraguard.yml"
    path.write_text(
        """policy_packs:
  - aws-foundation
fail_on: critical
output:
  format: json
  path: out.json
"""
    )

    config = load_config(path)

    assert config.policy_packs == ("aws-foundation",)
    assert config.fail_on == "critical"
    assert config.output_format == "json"
    assert config.output_path == "out.json"


def test_load_config_rejects_invalid_fail_on(tmp_path: Path) -> None:
    path = tmp_path / "bad.yml"
    path.write_text("fail_on: urgent\n")

    with pytest.raises(ConfigError, match="Unknown fail_on"):
        load_config(path)


def test_apply_overrides() -> None:
    config = TerraGuardConfig()
    updated = apply_overrides(config, policy_packs=("aws-eks",), fail_on="medium", output_format="sarif")

    assert updated.policy_packs == ("aws-eks",)
    assert updated.fail_on == "medium"
    assert updated.output_format == "sarif"
    assert config.fail_on == "high"
