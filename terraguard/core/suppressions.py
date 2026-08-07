from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

from terraguard.core.findings import Finding
from terraguard.exceptions import ConfigError

DEFAULT_SUPPRESSIONS_FILE = ".terraguard-ignore.yml"


@dataclass(frozen=True)
class Suppression:
    policy_id: str
    resource: str | None = None
    expires: date | None = None
    owner: str = ""
    ticket: str = ""
    reason: str = ""

    def matches(self, finding: Finding) -> bool:
        if self.policy_id != finding.policy_id and self.policy_id != "*":
            return False
        if self.resource is None or self.resource == "*":
            return True
        return bool(re.fullmatch(self.resource, finding.resource_address))

    def is_expired(self, today: date | None = None) -> bool:
        if self.expires is None:
            return False
        return self.expires < (today or datetime.now(tz=UTC).date())


def load_suppressions(path: Path | None = None) -> tuple[Suppression, ...]:
    suppressions_path = path or Path(DEFAULT_SUPPRESSIONS_FILE)
    if not suppressions_path.exists():
        return ()

    try:
        raw = yaml.safe_load(suppressions_path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {suppressions_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{suppressions_path} must contain a YAML mapping.")

    items = raw.get("suppressions", [])
    if not isinstance(items, list):
        raise ConfigError("suppressions must be a list.")

    parsed: list[Suppression] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ConfigError(f"suppressions[{index}] must be a mapping.")
        policy_id = str(item.get("policy_id", "")).strip()
        if not policy_id:
            raise ConfigError(f"suppressions[{index}].policy_id is required.")
        parsed.append(
            Suppression(
                policy_id=policy_id,
                resource=_optional_str(item.get("resource")),
                expires=_parse_date(item.get("expires"), index),
                owner=str(item.get("owner", "")),
                ticket=str(item.get("ticket", "")),
                reason=str(item.get("reason", "")),
            )
        )
    return tuple(parsed)


def apply_suppressions(
    findings: tuple[Finding, ...],
    suppressions: tuple[Suppression, ...],
    *,
    today: date | None = None,
) -> tuple[tuple[Finding, ...], tuple[Finding, ...], tuple[Suppression, ...]]:
    """Return active findings, suppressed findings, and expired suppressions."""
    active_rules = tuple(rule for rule in suppressions if not rule.is_expired(today))
    expired = tuple(rule for rule in suppressions if rule.is_expired(today))

    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in findings:
        if any(rule.matches(finding) for rule in active_rules):
            suppressed.append(finding)
        else:
            kept.append(finding)
    return tuple(kept), tuple(suppressed), expired


def _parse_date(value: Any, index: int) -> date | None:
    if value is None or value == "":
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise ConfigError(
            f"suppressions[{index}].expires must be YYYY-MM-DD, got {value!r}."
        ) from exc


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None
