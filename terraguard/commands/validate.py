from pathlib import Path

import typer

from terraguard.config import load_config
from terraguard.core.opa import validate_rego
from terraguard.core.policy_loader import policy_files

app = typer.Typer(no_args_is_help=False)


@app.callback(invoke_without_command=True)
def command(config: Path | None = typer.Option(None, "--config", help="Config file to validate.")) -> None:
    """Validate TerraGuard config and built-in Rego policy syntax."""
    loaded = load_config(config)
    files = policy_files(loaded.policy_packs)
    validate_rego(files)
    typer.echo(f"Validated config and {len(files)} policy files.")

