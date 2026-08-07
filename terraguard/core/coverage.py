from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from terraguard.core.policy_loader import PolicyPack, list_policy_packs


@dataclass(frozen=True)
class CoverageRow:
    resource_type: str
    count: int
    covered: bool
    policies: tuple[str, ...]


@dataclass(frozen=True)
class CoverageReport:
    rows: tuple[CoverageRow, ...]
    covered_types: int
    uncovered_types: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "covered_types": self.covered_types,
            "uncovered_types": self.uncovered_types,
            "resources": [
                {
                    "resource_type": row.resource_type,
                    "count": row.count,
                    "covered": row.covered,
                    "policies": list(row.policies),
                }
                for row in self.rows
            ],
        }


# Maps Terraform resource types to policy resource labels used in pack.yml.
RESOURCE_TYPE_MAP: dict[str, tuple[str, ...]] = {
    "aws_s3_bucket": ("s3",),
    "aws_s3_bucket_public_access_block": ("s3",),
    "aws_s3_bucket_versioning": ("s3",),
    "aws_instance": ("ec2",),
    "aws_ebs_volume": ("ebs",),
    "aws_kms_key": ("kms",),
    "aws_security_group": ("security-group",),
    "aws_vpc": ("vpc",),
    "aws_flow_log": ("vpc",),
    "aws_iam_policy": ("iam",),
    "aws_iam_role": ("iam",),
    "aws_db_instance": ("rds",),
    "aws_lb_listener": ("elb",),
    "aws_cloudtrail": ("cloudtrail",),
    "aws_eks_cluster": ("eks",),
    "aws_eks_node_group": ("eks",),
    "aws_eks_addon": ("eks",),
}


def build_coverage(
    plan: dict[str, Any],
    packs: tuple[PolicyPack, ...] | None = None,
    policy_roots: tuple[Path, ...] | None = None,
) -> CoverageReport:
    if packs is None:
        if policy_roots:
            packs = tuple(
                pack
                for root in policy_roots
                for pack in list_policy_packs(root)
            )
        else:
            packs = list_policy_packs()

    policies_by_resource: dict[str, list[str]] = {}
    for pack in packs:
        for policy in pack.policies:
            policies_by_resource.setdefault(policy.resource, []).append(policy.policy_id)

    counts: dict[str, int] = {}
    for change in plan.get("resource_changes") or []:
        resource_type = str(change.get("type") or "unknown")
        counts[resource_type] = counts.get(resource_type, 0) + 1

    rows: list[CoverageRow] = []
    covered = 0
    for resource_type, count in sorted(counts.items()):
        labels = RESOURCE_TYPE_MAP.get(resource_type, ())
        matched: list[str] = []
        for label in labels:
            matched.extend(policies_by_resource.get(label, []))
        is_covered = bool(matched)
        if is_covered:
            covered += 1
        rows.append(
            CoverageRow(
                resource_type=resource_type,
                count=count,
                covered=is_covered,
                policies=tuple(sorted(set(matched))),
            )
        )

    return CoverageReport(
        rows=tuple(rows),
        covered_types=covered,
        uncovered_types=len(rows) - covered,
    )
