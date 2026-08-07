import json
from pathlib import Path

from terraguard.core.coverage import build_coverage


def test_coverage_marks_known_types() -> None:
    plan = json.loads(
        (Path(__file__).resolve().parents[1] / "fixtures/tfplans/security_group_open_ssh.json").read_text()
    )
    report = build_coverage(plan)
    row = next(item for item in report.rows if item.resource_type == "aws_security_group")
    assert row.covered is True
    assert "TG_AWS_SG_001" in row.policies
