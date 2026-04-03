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
) -> None:
    """List available built-in policies."""
    table = Table(title="TerraGuard Policies")
    table.add_column("Pack")
    table.add_column("Policy ID")
    table.add_column("Severity")
    table.add_column("Resource")
    table.add_column("Title")

    for pack in list_policy_packs():
        if policy_pack and pack.name != policy_pack:
            continue
        for policy in pack.policies:
            if resource and policy.resource != resource:
                continue
            if severity and policy.severity != severity.lower():
                continue
            table.add_row(pack.name, policy.policy_id, policy.severity, policy.resource, policy.title)

    console.print(table)

