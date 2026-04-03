from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from terraguard.constants import CONFIG_FILE, DEFAULT_FAIL_ON, DEFAULT_POLICY_PACKS
from terraguard.exceptions import ConfigError


@dataclass(frozen=True)
class TerraGuardConfig:
    policy_packs: tuple[str, ...] = DEFAULT_POLICY_PACKS
    fail_on: str = DEFAULT_FAIL_ON
    output_format: str = "console"
    output_path: str | None = None


def load_config(path: Path | None = None) -> TerraGuardConfig:
    config_path = path or Path(CONFIG_FILE)
    if not config_path.exists():
        return TerraGuardConfig()

    try:
        raw = yaml.safe_load(config_path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {config_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{config_path} must contain a YAML mapping.")

    output = raw.get("output") or {}
    if not isinstance(output, dict):
        raise ConfigError("output must be a mapping when provided.")

    policy_packs = raw.get("policy_packs", list(DEFAULT_POLICY_PACKS))
    if not isinstance(policy_packs, list) or not all(isinstance(item, str) for item in policy_packs):
        raise ConfigError("policy_packs must be a list of strings.")

    return TerraGuardConfig(
        policy_packs=tuple(policy_packs),
        fail_on=str(raw.get("fail_on", DEFAULT_FAIL_ON)),
        output_format=str(output.get("format", "console")),
        output_path=_optional_str(output.get("path")),
    )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)

