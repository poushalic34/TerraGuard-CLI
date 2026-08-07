import json
from pathlib import Path

from typer.testing import CliRunner

from terraguard.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tfplans"


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "TerraGuard CLI" in result.output


def test_list_policies_command() -> None:
    result = runner.invoke(app, ["list-policies", "--as-json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    ids = {item["policy_id"] for item in payload}
    assert "TG_AWS_S3_001" in ids
    assert "TG_AWS_EKS_001" in ids


def test_scan_command_json_fails_on_violations(tmp_path: Path) -> None:
    output = tmp_path / "results.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--plan-json",
            str(FIXTURES / "security_group_open_ssh.json"),
            "--policy-pack",
            "aws-foundation",
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(output.read_text())
    assert payload["failed"] is True
    assert payload["findings"][0]["policy_id"] == "TG_AWS_SG_001"


def test_scan_command_passes_for_secure_plan() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--plan-json",
            str(FIXTURES / "secure_aws.json"),
            "--policy-pack",
            "aws-foundation",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["failed"] is False
    assert payload["summary"]["total"] == 0


def test_scan_missing_plan_exits_2() -> None:
    result = runner.invoke(app, ["scan", "--plan-json", "/tmp/missing-terraguard-plan.json"])

    assert result.exit_code == 2
    assert "Error:" in result.output


def test_validate_command() -> None:
    result = runner.invoke(app, ["validate", "--policy-pack", "aws-foundation"])

    assert result.exit_code == 0
    assert "Validated config" in result.output


def test_explain_command() -> None:
    result = runner.invoke(app, ["explain", "TG_AWS_SG_001"])

    assert result.exit_code == 0
    assert "TG_AWS_SG_001" in result.output
    assert "Restrict SSH ingress" in result.output


def test_explain_json() -> None:
    result = runner.invoke(app, ["explain", "--as-json", "TG_AWS_EKS_001"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["policy_id"] == "TG_AWS_EKS_001"
    assert "remediation" in payload


def test_report_command(tmp_path: Path) -> None:
    input_path = tmp_path / "results.json"
    input_path.write_text(
        json.dumps(
            {
                "fail_on": "high",
                "findings": [
                    {
                        "policy_id": "TG_AWS_SG_001",
                        "title": "Security groups must not expose SSH to the internet",
                        "severity": "critical",
                        "resource_type": "aws_security_group",
                        "resource_address": "aws_security_group.open_ssh",
                        "message": "open ssh",
                        "remediation": "restrict",
                    }
                ],
            }
        )
    )
    output = tmp_path / "report.md"
    result = runner.invoke(
        app,
        ["report", "--input", str(input_path), "--format", "markdown", "--output", str(output)],
    )

    assert result.exit_code == 0
    assert "TG_AWS_SG_001" in output.read_text()


def test_init_command(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])

    assert result.exit_code == 0
    assert (tmp_path / ".terraguard.yml").exists()
    assert (tmp_path / ".terraguard").is_dir()


def test_doctor_command() -> None:
    result = runner.invoke(app, ["doctor", "--as-json"])

    assert result.exit_code in (0, 1)
    payload = json.loads(result.output)
    assert "checks" in payload
    assert any(check["check"] == "opa" for check in payload["checks"])


def test_coverage_command() -> None:
    result = runner.invoke(
        app,
        ["coverage", "--plan-json", str(FIXTURES / "security_group_open_ssh.json"), "--as-json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["covered_types"] >= 1


def test_generate_pre_commit(tmp_path: Path) -> None:
    output = tmp_path / ".pre-commit-config.yaml"
    result = runner.invoke(app, ["generate", "pre-commit", "--output", str(output)])
    assert result.exit_code == 0
    assert "terraguard validate" in output.read_text()


def test_comment_command_renders_markdown(tmp_path: Path) -> None:
    input_path = tmp_path / "results.json"
    input_path.write_text(Path("examples/reports/sample-results.json").read_text())
    output = tmp_path / "comment.md"
    result = runner.invoke(
        app,
        ["comment", "--input", str(input_path), "--output", str(output), "--title", "Demo"],
    )
    assert result.exit_code == 0
    body = output.read_text()
    assert "<!-- terraguard-scan-report -->" in body
    assert "TG_AWS_SG_001" in body
    assert "Demo" in body


def test_generate_github_action_includes_pr_comment(tmp_path: Path) -> None:
    output = tmp_path / "terraguard.yml"
    result = runner.invoke(app, ["generate", "github-action", "--output", str(output)])
    assert result.exit_code == 0
    text = output.read_text()
    assert "terraguard comment" in text
    assert "pull-requests: write" in text
