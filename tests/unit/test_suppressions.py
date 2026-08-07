from datetime import date
from pathlib import Path

import pytest

from terraguard.core.findings import Finding
from terraguard.core.suppressions import apply_suppressions, load_suppressions
from terraguard.exceptions import ConfigError


def _finding(policy_id: str = "TG_AWS_SG_001", address: str = "aws_security_group.open_ssh") -> Finding:
    return Finding(
        policy_id=policy_id,
        title="t",
        severity="critical",
        resource_type="aws_security_group",
        resource_address=address,
        message="m",
        remediation="r",
    )


def test_load_and_apply_suppressions(tmp_path: Path) -> None:
    path = tmp_path / ".terraguard-ignore.yml"
    path.write_text(
        """
suppressions:
  - policy_id: TG_AWS_SG_001
    resource: aws_security_group\\.open_ssh
    expires: "2099-01-01"
    owner: platform@example.com
    ticket: SEC-1
    reason: temporary
"""
    )
    rules = load_suppressions(path)
    active, suppressed, expired = apply_suppressions((_finding(), _finding("TG_AWS_EBS_001", "aws_ebs_volume.x")), rules)

    assert len(suppressed) == 1
    assert suppressed[0].policy_id == "TG_AWS_SG_001"
    assert len(active) == 1
    assert expired == ()


def test_expired_suppressions(tmp_path: Path) -> None:
    path = tmp_path / "ignore.yml"
    path.write_text(
        """
suppressions:
  - policy_id: TG_AWS_SG_001
    expires: "2020-01-01"
"""
    )
    rules = load_suppressions(path)
    active, suppressed, expired = apply_suppressions((_finding(),), rules, today=date(2026, 1, 1))
    assert len(active) == 1
    assert suppressed == ()
    assert len(expired) == 1


def test_invalid_suppressions(tmp_path: Path) -> None:
    path = tmp_path / "bad.yml"
    path.write_text("suppressions:\n  - expires: nope\n")
    with pytest.raises(ConfigError):
        load_suppressions(path)
