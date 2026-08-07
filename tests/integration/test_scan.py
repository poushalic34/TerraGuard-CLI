from pathlib import Path

import pytest

from terraguard.config import TerraGuardConfig
from terraguard.core.policy_loader import policy_files
from terraguard.core.scanner import scan_plan
from terraguard.exceptions import TerraformPlanError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tfplans"


def test_scan_foundation_violations() -> None:
    result = scan_plan(
        TerraGuardConfig(policy_packs=("aws-foundation",), fail_on="high"),
        plan_json=FIXTURES / "aws_foundation_violations.json",
    )

    ids = {finding.policy_id for finding in result.findings}
    assert {
        "TG_AWS_S3_001",
        "TG_AWS_S3_002",
        "TG_AWS_EC2_001",
        "TG_AWS_EBS_001",
        "TG_AWS_SG_001",
        "TG_AWS_SG_002",
        "TG_AWS_SG_003",
        "TG_AWS_IAM_001",
        "TG_AWS_IAM_002",
        "TG_AWS_RDS_001",
        "TG_AWS_RDS_002",
        "TG_AWS_CT_001",
        "TG_AWS_CT_002",
        "TG_AWS_ELB_001",
        "TG_AWS_ELB_002",
    } <= ids
    assert "TG_AWS_KMS_001" in ids
    assert "TG_AWS_VPC_001" in ids
    assert result.failed is True


def test_scan_eks_violations() -> None:
    result = scan_plan(
        TerraGuardConfig(policy_packs=("aws-eks",), fail_on="high"),
        plan_json=FIXTURES / "eks_violations.json",
    )

    ids = {finding.policy_id for finding in result.findings}
    assert {
        "TG_AWS_EKS_001",
        "TG_AWS_EKS_002",
        "TG_AWS_EKS_003",
        "TG_AWS_EKS_004",
        "TG_AWS_EKS_005",
        "TG_AWS_EKS_006",
        "TG_AWS_EKS_007",
        "TG_AWS_EKS_008",
        "TG_AWS_EKS_009",
        "TG_AWS_EKS_010",
        "TG_AWS_EKS_011",
    } <= ids
    assert result.failed is True


def test_scan_secure_plan_passes() -> None:
    result = scan_plan(
        TerraGuardConfig(policy_packs=("aws-foundation",), fail_on="high"),
        plan_json=FIXTURES / "secure_aws.json",
    )

    assert result.findings == ()
    assert result.failed is False


def test_scan_requires_plan_input() -> None:
    with pytest.raises(TerraformPlanError, match="Provide either"):
        scan_plan(TerraGuardConfig())


def test_policy_files_are_deduplicated() -> None:
    files = policy_files(("aws-eks",))
    assert len(files) == len({path.resolve() for path in files})
    assert any(path.name == "eks_cluster.rego" for path in files)


def test_scan_changed_only() -> None:
    result = scan_plan(
        TerraGuardConfig(policy_packs=("aws-foundation",), fail_on="high", changed_only=True),
        plan_json=FIXTURES / "changed_only.json",
    )
    addresses = {finding.resource_address for finding in result.findings}
    assert "aws_security_group.open_ssh" in addresses
    assert "aws_security_group.noop" not in addresses


def test_scan_with_suppressions(tmp_path: Path) -> None:
    ignore = tmp_path / "ignore.yml"
    ignore.write_text(
        """
suppressions:
  - policy_id: TG_AWS_SG_001
    resource: aws_security_group\\.open_ssh
    expires: "2099-01-01"
    owner: platform
    ticket: SEC-1
    reason: demo
"""
    )
    result = scan_plan(
        TerraGuardConfig(
            policy_packs=("aws-foundation",),
            fail_on="critical",
            suppressions_path=ignore,
        ),
        plan_json=FIXTURES / "security_group_open_ssh.json",
    )
    assert result.findings == ()
    assert len(result.suppressed) == 1
    assert result.failed is False
