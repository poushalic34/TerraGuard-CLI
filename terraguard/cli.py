import typer
from rich.console import Console

from terraguard.commands import (
    comment,
    coverage,
    doctor,
    explain,
    generate,
    init,
    list_policies,
    packs,
    report,
    scan,
    validate,
    version,
)
from terraguard.exceptions import TerraGuardError

console = Console()
app = typer.Typer(
    name="terraguard",
    help="Shift-left Terraform policy validation with OPA/Rego for AWS and EKS.",
    no_args_is_help=True,
)

app.add_typer(init.app, name="init")
app.add_typer(scan.app, name="scan")
app.add_typer(explain.app, name="explain")
app.add_typer(generate.app, name="generate")
app.add_typer(list_policies.app, name="list-policies")
app.add_typer(validate.app, name="validate")
app.add_typer(report.app, name="report")
app.add_typer(comment.app, name="comment")
app.add_typer(coverage.app, name="coverage")
app.add_typer(packs.app, name="packs")
app.add_typer(doctor.app, name="doctor")
app.add_typer(version.app, name="version")


@app.callback()
def main() -> None:
    """Run TerraGuard CLI."""


def run() -> None:
    """Console script entry point with user-facing error handling."""
    try:
        app()
    except TerraGuardError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise SystemExit(2) from exc

