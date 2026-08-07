from terraguard.core.findings import Finding, ScanResult
from terraguard.output import html, json, markdown, sarif


def _sample_result() -> ScanResult:
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
            ),
        ),
        fail_on="high",
    )


def test_json_render_includes_summary() -> None:
    payload = json.render(_sample_result())
    assert '"failed": true' in payload
    assert "TG_AWS_SG_001" in payload


def test_markdown_render_includes_finding() -> None:
    rendered = markdown.render(_sample_result())
    assert "# TerraGuard Report" in rendered
    assert "TG_AWS_SG_001" in rendered
    assert "Remediation" in rendered


def test_html_render_wraps_markdown() -> None:
    rendered = html.render(_sample_result())
    assert "<!doctype html>" in rendered
    assert "TG_AWS_SG_001" in rendered


def test_sarif_render_has_rules_and_results() -> None:
    payload = sarif.render(_sample_result())
    assert '"version": "2.1.0"' in payload
    assert "TG_AWS_SG_001" in payload
    assert '"level": "error"' in payload


def test_markdown_empty_findings() -> None:
    result = ScanResult(findings=(), fail_on="high")
    assert "No policy violations found." in markdown.render(result)
