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
    why: str = ""
    remediation: str = ""
    controls: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyPack:
    name: str
    description: str
    policies: tuple[Policy, ...]
    path: Path


def resolve_policy_roots(
    builtin: Path = BUILTIN_POLICY_ROOT,
    extra: tuple[Path, ...] = (),
) -> tuple[Path, ...]:
    roots = [builtin, *extra]
    return tuple(root for root in roots if root.exists())


def list_policy_packs(policy_root: Path = BUILTIN_POLICY_ROOT) -> tuple[PolicyPack, ...]:
    if not policy_root.exists():
        return ()

    packs = []
    for pack_path in sorted(path for path in policy_root.iterdir() if path.is_dir()):
        if not (pack_path / "pack.yml").exists():
            continue
        packs.append(load_policy_pack(pack_path.name, policy_root))
    return tuple(packs)


def list_all_policy_packs(policy_roots: tuple[Path, ...]) -> tuple[PolicyPack, ...]:
    packs: list[PolicyPack] = []
    seen: set[str] = set()
    for root in policy_roots:
        for pack in list_policy_packs(root):
            if pack.name in seen:
                continue
            seen.add(pack.name)
            packs.append(pack)
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
            why=str(item.get("why", "")),
            remediation=str(item.get("remediation", "")),
            controls=_controls(item.get("controls")),
        )
        for item in raw.get("policies", [])
    )
    return PolicyPack(
        name=str(raw.get("name", name)),
        description=str(raw.get("description", "")),
        policies=policies,
        path=pack_path,
    )


def find_pack_root(name: str, policy_roots: tuple[Path, ...]) -> Path:
    for root in policy_roots:
        candidate = root / name / "pack.yml"
        if candidate.exists():
            return root
    raise PolicyError(f"Policy pack '{name}' was not found in: {', '.join(str(r) for r in policy_roots)}")


def policy_files(
    pack_names: tuple[str, ...],
    policy_root: Path = BUILTIN_POLICY_ROOT,
    policy_roots: tuple[Path, ...] | None = None,
) -> tuple[Path, ...]:
    roots = policy_roots or (policy_root,)
    files: list[Path] = []
    seen: set[Path] = set()
    for pack_name in pack_names:
        root = find_pack_root(pack_name, roots)
        pack = load_policy_pack(pack_name, root)
        for policy in pack.policies:
            if not policy.path.exists():
                raise PolicyError(f"Policy file is missing: {policy.path}")
            resolved = policy.path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append(policy.path)
    return tuple(files)


def find_policy(
    policy_id: str,
    policy_root: Path = BUILTIN_POLICY_ROOT,
    policy_roots: tuple[Path, ...] | None = None,
) -> Policy | None:
    roots = policy_roots or (policy_root,)
    for pack in list_all_policy_packs(roots):
        for policy in pack.policies:
            if policy.policy_id == policy_id:
                return policy
    return None


def _controls(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return ()


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"{path} must contain a YAML mapping.")
    return raw
