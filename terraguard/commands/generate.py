from pathlib import Path

import typer

app = typer.Typer(no_args_is_help=True)

WORKFLOW = """name: TerraGuard

on:
  pull_request:
    paths:
      - "infra/**"
      - ".terraguard.yml"

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_wrapper: false
      - name: Install OPA
        run: |
          curl -fsSL -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
          chmod +x opa
          sudo mv opa /usr/local/bin/opa
      - name: Install TerraGuard
        run: pip install terraguard-cli
      - name: Terraform plan
        working-directory: infra
        run: |
          terraform init -input=false
          terraform validate
          terraform plan -out=tfplan -input=false
      - name: TerraGuard scan
        id: scan
        working-directory: infra
        continue-on-error: true
        run: |
          terraguard scan --tfplan tfplan --format sarif --output terraguard.sarif
          terraguard scan --tfplan tfplan --format json --output terraguard-results.json
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: infra/terraguard.sarif
      - name: Post sticky PR comment
        if: github.event_name == 'pull_request' && always()
        working-directory: infra
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          terraguard comment --input terraguard-results.json --post \\
            --title "TerraGuard Policy Scan"
      - name: Fail job when scan failed
        if: steps.scan.outcome == 'failure'
        run: exit 1
"""

PRE_COMMIT = """repos:
  - repo: local
    hooks:
      - id: terraguard-validate
        name: terraguard validate
        entry: terraguard validate
        language: system
        pass_filenames: false
      - id: terraguard-scan-plan-json
        name: terraguard scan plan json
        entry: bash -c 'test -f tfplan.json && terraguard scan --plan-json tfplan.json --fail-on high || true'
        language: system
        pass_filenames: false
        files: '(^|/)tfplan\\.json$'
"""

POLICY_TEMPLATE = """package terraguard

import rego.v1

deny contains finding if {{
	resource := input.resource_changes[_]
	resource.type == "{resource_type}"
	# TODO: add deny conditions

	finding := {{
		"policy_id": "{policy_id}",
		"title": "{title}",
		"severity": "{severity}",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "TODO: describe the violation.",
		"remediation": "TODO: describe how to fix it.",
	}}
}}
"""

POLICY_TEST_TEMPLATE = """package terraguard

import rego.v1

test_{slug}_denied if {{
	result := deny with input as {{"resource_changes": [{{
		"address": "{resource_type}.example",
		"type": "{resource_type}",
		"change": {{"after": {{}}}},
	}}]}}
	# Adjust fixture until this assertion is meaningful.
	count([finding | some finding in result; finding.policy_id == "{policy_id}"]) >= 0
}}
"""


@app.command("github-action")
def github_action(
    output: Path = typer.Option(Path(".github/workflows/terraguard.yml"), "--output"),
) -> None:
    """Generate a starter GitHub Actions workflow with SARIF upload."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(WORKFLOW)
    typer.echo(f"Generated {output}")


@app.command("pre-commit")
def pre_commit(
    output: Path = typer.Option(Path(".pre-commit-config.yaml"), "--output"),
) -> None:
    """Generate a local pre-commit config for TerraGuard."""
    output.write_text(PRE_COMMIT)
    typer.echo(f"Generated {output}")


@app.command("policy")
def policy(
    policy_id: str = typer.Option(..., "--id", help="Policy ID, e.g. TG_AWS_RDS_001."),
    resource_type: str = typer.Option(
        ..., "--resource-type", help="Terraform type, e.g. aws_db_instance."
    ),
    pack: str = typer.Option("aws-foundation", "--pack", help="Target built-in pack name."),
    title: str = typer.Option("TODO policy title", "--title"),
    severity: str = typer.Option("high", "--severity"),
    resource: str = typer.Option("unknown", "--resource", help="Pack resource label."),
) -> None:
    """Scaffold a Rego policy, pack.yml stub line guidance, and opa test."""
    policies_dir = Path("policy-packs") / pack / "policies"
    tests_dir = Path("policy-packs") / pack / "tests"
    if not policies_dir.exists():
        raise typer.BadParameter(f"Pack policies directory not found: {policies_dir}")

    slug = policy_id.lower().replace("-", "_")
    file_stem = resource_type.removeprefix("aws_").replace("-", "_")
    policy_path = policies_dir / f"{file_stem}.rego"
    test_path = tests_dir / f"{file_stem}_test.rego"
    tests_dir.mkdir(parents=True, exist_ok=True)

    if not policy_path.exists():
        policy_path.write_text(
            POLICY_TEMPLATE.format(
                resource_type=resource_type,
                policy_id=policy_id,
                title=title,
                severity=severity,
            )
        )
        typer.echo(f"Created {policy_path}")
    else:
        typer.echo(f"Policy file already exists: {policy_path} (left unchanged)")

    if not test_path.exists():
        test_path.write_text(
            POLICY_TEST_TEMPLATE.format(
                slug=slug,
                resource_type=resource_type,
                policy_id=policy_id,
            )
        )
        typer.echo(f"Created {test_path}")
    else:
        typer.echo(f"Test file already exists: {test_path} (left unchanged)")

    typer.echo("")
    typer.echo("Add this entry to pack.yml:")
    typer.echo(
        "\n".join(
            [
                f"  - id: {policy_id}",
                f"    title: {title}",
                f"    severity: {severity}",
                f"    resource: {resource}",
                f"    file: {policy_path.name}",
                "    controls: []",
                "    why: TODO",
                "    remediation: TODO",
            ]
        )
    )
