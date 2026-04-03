from pathlib import Path

import typer

app = typer.Typer(no_args_is_help=True)


@app.command("github-action")
def github_action(output: Path = typer.Option(Path(".github/workflows/terraguard.yml"), "--output")) -> None:
    """Generate a starter GitHub Actions workflow."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        """name: TerraGuard

on:
  pull_request:
    paths:
      - "infra/**"

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - name: Install TerraGuard
        run: pip install -e .
      - name: Terraform plan
        working-directory: infra
        run: |
          terraform init -input=false
          terraform validate
          terraform plan -out=tfplan -input=false
      - name: TerraGuard scan
        working-directory: infra
        run: terraguard scan --tfplan tfplan --format json --output terraguard-results.json
"""
    )
    typer.echo(f"Generated {output}")

