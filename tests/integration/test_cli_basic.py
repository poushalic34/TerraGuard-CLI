from typer.testing import CliRunner

from terraguard.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "TerraGuard CLI" in result.output


def test_list_policies_command() -> None:
    result = runner.invoke(app, ["list-policies"])

    assert result.exit_code == 0
    assert "TG_AWS_S3_001" in result.output

