from unittest.mock import patch

from terraguard.core.findings import Finding, ScanResult
from terraguard.output.pr_comment import COMMENT_MARKER, post_or_update_comment, render


def _result() -> ScanResult:
    return ScanResult(
        findings=(
            Finding(
                policy_id="TG_AWS_SG_001",
                title="Security groups must not expose SSH to the internet",
                severity="critical",
                resource_type="aws_security_group",
                resource_address="aws_security_group.open_ssh",
                message="Security group allows SSH ingress from 0.0.0.0/0.",
                remediation="Restrict SSH ingress.",
                controls=("CIS-AWS-5.2",),
                fix_hcl='cidr_blocks = ["10.0.0.0/8"]\n',
            ),
        ),
        fail_on="high",
        suppressed=(),
        expired_suppressions=(),
    )


def test_render_pr_comment_includes_marker_and_finding() -> None:
    body = render(_result())
    assert COMMENT_MARKER in body
    assert "FAILED" in body
    assert "TG_AWS_SG_001" in body
    assert "```hcl" in body
    assert "CIS-AWS-5.2" in body


def test_render_pr_comment_passed() -> None:
    body = render(ScanResult(findings=(), fail_on="high"))
    assert "PASSED" in body
    assert "No policy violations found." in body


def test_post_updates_existing_sticky_comment() -> None:
    existing = {"id": 99, "body": f"{COMMENT_MARKER}\nold"}
    updated = {
        "id": 99,
        "html_url": "https://example.test/comment/99",
        "updated_at": "t",
        "created_at": "t0",
    }

    with patch("terraguard.output.pr_comment._request") as request:
        request.side_effect = [[existing], updated]
        response = post_or_update_comment(
            "new body",
            repository="acme/infra",
            pr_number=7,
            token="token",
            api_url="https://api.github.com",
        )

    assert response["id"] == 99
    assert request.call_args_list[1].args[0] == "PATCH"


def test_post_creates_comment_when_missing() -> None:
    created = {
        "id": 1,
        "html_url": "https://example.test/comment/1",
        "created_at": "t",
        "updated_at": "t",
    }
    with patch("terraguard.output.pr_comment._request") as request:
        request.side_effect = [[], created]
        response = post_or_update_comment(
            "body",
            repository="acme/infra",
            pr_number=3,
            token="token",
        )

    assert response["id"] == 1
    assert request.call_args_list[1].args[0] == "POST"
