import json

import typer
from rich.console import Console
from rich.table import Table

from terraguard.core.policy_loader import list_policy_packs

app = typer.Typer(no_args_is_help=False)
console = Console()


@app.callback(invoke_without_command=True)
def command(
    policy_pack: str | None = typer.Option(None, "--policy-pack", help="Filter by policy pack."),
    resource: str | None = typer.Option(None, "--resource", help="Filter by resource area."),
    severity: str | None = typer.Option(None, "--severity", help="Filter by severity."),
    as_json: bool = typer.Option(False, "--as-json", help="Print policies as JSON."),
) -> None:
    """List available built-in policies."""
    rows = []
    for pack in list_policy_packs():
        if policy_pack and pack.name != policy_pack:
            continue
        for policy in pack.policies:
            if resource and policy.resource != resource:
                continue
            if severity and policy.severity != severity.lower():
                continue
            rows.append(
                {
                    "pack": pack.name,
                    "policy_id": policy.policy_id,
                    "severity": policy.severity,
                    "resource": policy.resource,
                    "controls": list(policy.controls),
                    "title": policy.title,
                }
            )

    if as_json:
        typer.echo(json.dumps(rows, indent=2))
        return

    table = Table(title="TerraGuard Policies", expand=True)
    table.add_column("Pack", no_wrap=True)
    table.add_column("Policy ID", no_wrap=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Resource", no_wrap=True)
    table.add_column("Title")

    for row in rows:
        table.add_row(
            row["pack"],
            row["policy_id"],
            row["severity"],
            row["resource"],
            row["title"],
        )

    console.print(table)
