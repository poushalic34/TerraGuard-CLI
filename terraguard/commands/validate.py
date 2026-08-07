from pathlib import Path

import typer

from terraguard.config import load_config
from terraguard.core.opa import validate_rego
from terraguard.core.policy_loader import policy_files
from terraguard.exceptions import TerraGuardError

app = typer.Typer(no_args_is_help=False)


@app.callback(invoke_without_command=True)
def command(
    config: Path | None = typer.Option(None, "--config", help="Config file to validate."),
    policy_pack: list[str] | None = typer.Option(
        None,
        "--policy-pack",
        help="Validate a specific built-in policy pack. Repeatable.",
    ),
) -> None:
    """Validate TerraGuard config and built-in Rego policy syntax."""
    try:
        loaded = load_config(config)
        packs = tuple(policy_pack) if policy_pack else loaded.policy_packs
        files = policy_files(packs)
        validate_rego(files)
    except TerraGuardError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(f"Validated config and {len(files)} policy files.")
