import typer

from terraguard.core.policy_loader import find_policy

app = typer.Typer(no_args_is_help=True)


@app.callback(invoke_without_command=True)
def command(policy_id: str = typer.Argument(..., help="Policy ID to explain.")) -> None:
    """Explain a policy and its remediation."""
    policy = find_policy(policy_id)
    if policy is None:
        raise typer.BadParameter(f"Unknown policy ID: {policy_id}")

    typer.echo(f"{policy.policy_id}: {policy.title}")
    typer.echo(f"Severity: {policy.severity}")
    typer.echo(f"Resource: {policy.resource}")
    typer.echo("")
    typer.echo("Why it matters:")
    typer.echo("This policy catches insecure Terraform before infrastructure is applied.")
    typer.echo("")
    typer.echo("How to fix:")
    typer.echo("Review the matching Terraform resource and apply the remediation described in the policy.")

