import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from terraguard.config import load_config
from terraguard.constants import BUILTIN_POLICY_ROOT, CUSTOM_POLICY_ROOT
from terraguard.core.coverage import build_coverage
from terraguard.core.policy_loader import resolve_policy_roots
from terraguard.core.terraform import load_plan_json, show_tfplan
from terraguard.exceptions import TerraGuardError

app = typer.Typer(no_args_is_help=False)
console = Console()


@app.callback(invoke_without_command=True)
def command(
    tfplan: Path | None = typer.Option(None, "--tfplan", help="Terraform/OpenTofu binary plan."),
    plan_json: Path | None = typer.Option(None, "--plan-json", help="Plan JSON file."),
    config: Path | None = typer.Option(None, "--config", help="Config path."),
    as_json: bool = typer.Option(False, "--as-json", help="Print JSON coverage report."),
) -> None:
    """Show which plan resource types are covered by selected policy packs."""
    try:
        loaded = load_config(config)
        if tfplan is None and plan_json is None:
            raise typer.BadParameter("Provide --tfplan or --plan-json.")
        if tfplan is not None and plan_json is not None:
            raise typer.BadParameter("Use only one of --tfplan or --plan-json.")

        plan = (
            show_tfplan(tfplan, binary=loaded.terraform_binary)
            if tfplan is not None
            else load_plan_json(plan_json)  # type: ignore[arg-type]
        )
        extras = list(loaded.policy_dirs)
        if CUSTOM_POLICY_ROOT.exists():
            extras.append(CUSTOM_POLICY_ROOT)
        roots = resolve_policy_roots(BUILTIN_POLICY_ROOT, tuple(extras))
        report = build_coverage(plan, policy_roots=roots)
    except TerraGuardError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if as_json:
        typer.echo(json.dumps(report.to_dict(), indent=2))
        return

    table = Table(title="TerraGuard Policy Coverage")
    table.add_column("Resource type")
    table.add_column("Count")
    table.add_column("Covered")
    table.add_column("Policies")
    for row in report.rows:
        table.add_row(
            row.resource_type,
            str(row.count),
            "yes" if row.covered else "no",
            ", ".join(row.policies) or "-",
        )
    console.print(table)
    console.print(
        f"Covered types: {report.covered_types} | Uncovered types: {report.uncovered_types}"
    )
