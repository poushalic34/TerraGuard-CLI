from pathlib import Path

import typer

from terraguard.constants import CONFIG_FILE

app = typer.Typer(no_args_is_help=False)

CONFIG_TEMPLATE = """version: 1
policy_packs:
  - aws-foundation
  - aws-eks
fail_on: high
output:
  format: console
  path: null
"""


@app.callback(invoke_without_command=True)
def command(force: bool = typer.Option(False, "--force", help="Overwrite existing config.")) -> None:
    """Initialize TerraGuard in the current repository."""
    config_path = Path(CONFIG_FILE)
    if config_path.exists() and not force:
        typer.echo(f"{CONFIG_FILE} already exists. Use --force to overwrite.")
        return

    config_path.write_text(CONFIG_TEMPLATE)
    Path(".terraguard").mkdir(exist_ok=True)
    typer.echo(f"Created {CONFIG_FILE} and .terraguard/")

