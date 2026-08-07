from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

from terraguard.constants import (
    CONFIG_FILE,
    DEFAULT_FAIL_ON,
    DEFAULT_POLICY_PACKS,
    SEVERITIES,
)
from terraguard.exceptions import ConfigError


@dataclass(frozen=True)
class TerraGuardConfig:
    policy_packs: tuple[str, ...] = DEFAULT_POLICY_PACKS
    fail_on: str = DEFAULT_FAIL_ON
    output_format: str = "console"
    output_path: str | None = None
    policy_dirs: tuple[Path, ...] = ()
    suppressions_path: Path | None = None
    changed_only: bool = False
    terraform_binary: str | None = None


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

    fail_on = str(raw.get("fail_on", DEFAULT_FAIL_ON)).lower()
    _validate_fail_on(fail_on)

    policy_dirs_raw = raw.get("policy_dirs") or []
    if not isinstance(policy_dirs_raw, list) or not all(
        isinstance(item, str) for item in policy_dirs_raw
    ):
        raise ConfigError("policy_dirs must be a list of strings.")

    suppressions = raw.get("suppressions_path")
    binary = raw.get("terraform_binary")

    return TerraGuardConfig(
        policy_packs=tuple(policy_packs),
        fail_on=fail_on,
        output_format=str(output.get("format", "console")),
        output_path=_optional_str(output.get("path")),
        policy_dirs=tuple(Path(item) for item in policy_dirs_raw),
        suppressions_path=Path(suppressions) if suppressions else None,
        changed_only=bool(raw.get("changed_only", False)),
        terraform_binary=str(binary) if binary else None,
    )


def apply_overrides(
    config: TerraGuardConfig,
    *,
    policy_packs: tuple[str, ...] | None = None,
    fail_on: str | None = None,
    output_format: str | None = None,
    output_path: str | None = None,
    policy_dirs: tuple[Path, ...] | None = None,
    suppressions_path: Path | None = None,
    changed_only: bool | None = None,
    terraform_binary: str | None = None,
) -> TerraGuardConfig:
    updates: dict[str, Any] = {}
    if policy_packs is not None:
        updates["policy_packs"] = policy_packs
    if fail_on is not None:
        normalized = fail_on.lower()
        _validate_fail_on(normalized)
        updates["fail_on"] = normalized
    if output_format is not None:
        updates["output_format"] = output_format
    if output_path is not None:
        updates["output_path"] = output_path
    if policy_dirs is not None:
        updates["policy_dirs"] = policy_dirs
    if suppressions_path is not None:
        updates["suppressions_path"] = suppressions_path
    if changed_only is not None:
        updates["changed_only"] = changed_only
    if terraform_binary is not None:
        updates["terraform_binary"] = terraform_binary
    return replace(config, **updates) if updates else config


def _validate_fail_on(fail_on: str) -> None:
    if fail_on not in SEVERITIES:
        raise ConfigError(
            f"Unknown fail_on '{fail_on}'. Expected one of: {', '.join(SEVERITIES)}."
        )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
