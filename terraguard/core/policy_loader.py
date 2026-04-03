from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from terraguard.constants import BUILTIN_POLICY_ROOT
from terraguard.exceptions import PolicyError


@dataclass(frozen=True)
class Policy:
    policy_id: str
    title: str
    severity: str
    resource: str
    path: Path


@dataclass(frozen=True)
class PolicyPack:
    name: str
    description: str
    policies: tuple[Policy, ...]
    path: Path


def list_policy_packs(policy_root: Path = BUILTIN_POLICY_ROOT) -> tuple[PolicyPack, ...]:
    if not policy_root.exists():
        return ()

    packs = []
    for pack_path in sorted(path for path in policy_root.iterdir() if path.is_dir()):
        packs.append(load_policy_pack(pack_path.name, policy_root))
    return tuple(packs)


def load_policy_pack(name: str, policy_root: Path = BUILTIN_POLICY_ROOT) -> PolicyPack:
    pack_path = policy_root / name
    metadata_path = pack_path / "pack.yml"
    if not metadata_path.exists():
        raise PolicyError(f"Policy pack '{name}' does not exist or is missing pack.yml.")

    raw = _read_yaml(metadata_path)
    policies = tuple(
        Policy(
            policy_id=str(item["id"]),
            title=str(item["title"]),
            severity=str(item.get("severity", "medium")).lower(),
            resource=str(item.get("resource", "unknown")),
            path=pack_path / "policies" / str(item["file"]),
        )
        for item in raw.get("policies", [])
    )
    return PolicyPack(
        name=str(raw.get("name", name)),
        description=str(raw.get("description", "")),
        policies=policies,
        path=pack_path,
    )


def policy_files(pack_names: tuple[str, ...], policy_root: Path = BUILTIN_POLICY_ROOT) -> tuple[Path, ...]:
    files: list[Path] = []
    for pack_name in pack_names:
        pack = load_policy_pack(pack_name, policy_root)
        for policy in pack.policies:
            if not policy.path.exists():
                raise PolicyError(f"Policy file is missing: {policy.path}")
            files.append(policy.path)
    return tuple(files)


def find_policy(policy_id: str, policy_root: Path = BUILTIN_POLICY_ROOT) -> Policy | None:
    for pack in list_policy_packs(policy_root):
        for policy in pack.policies:
            if policy.policy_id == policy_id:
                return policy
    return None


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"{path} must contain a YAML mapping.")
    return raw

