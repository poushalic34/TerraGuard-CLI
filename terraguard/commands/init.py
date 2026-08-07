from pathlib import Path

import typer

from terraguard.constants import CONFIG_FILE

app = typer.Typer(no_args_is_help=False)

CONFIG_TEMPLATE = """version: 1
policy_packs:
  - aws-foundation
  - aws-eks
fail_on: high
changed_only: false
# policy_dirs:
#   - .terraguard/packs
# suppressions_path: .terraguard-ignore.yml
# terraform_binary: terraform
output:
  format: console
  path: null
"""

IGNORE_TEMPLATE = """suppressions:
  # - policy_id: TG_AWS_SG_001
  #   resource: aws_security_group.open_ssh
  #   expires: "2026-12-31"
  #   owner: platform@example.com
  #   ticket: SEC-123
  #   reason: Temporary exception pending SSM migration
"""


@app.callback(invoke_without_command=True)
def command(force: bool = typer.Option(False, "--force", help="Overwrite existing config.")) -> None:
    """Initialize TerraGuard in the current repository."""
    config_path = Path(CONFIG_FILE)
    ignore_path = Path(".terraguard-ignore.yml")
    if config_path.exists() and not force:
        typer.echo(f"{CONFIG_FILE} already exists. Use --force to overwrite.")
        return

    config_path.write_text(CONFIG_TEMPLATE)
    Path(".terraguard").mkdir(exist_ok=True)
    Path(".terraguard/packs").mkdir(exist_ok=True)
    if not ignore_path.exists() or force:
        ignore_path.write_text(IGNORE_TEMPLATE)
    typer.echo(f"Created {CONFIG_FILE}, .terraguard/, and .terraguard-ignore.yml")
