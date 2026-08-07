import json

import typer

from terraguard.constants import BUILTIN_POLICY_ROOT, CUSTOM_POLICY_ROOT
from terraguard.core.policy_loader import find_policy, resolve_policy_roots
from terraguard.core.remediation import remediation_hcl
from terraguard.exceptions import TerraGuardError

app = typer.Typer(no_args_is_help=True)


@app.callback(invoke_without_command=True)
def command(
    policy_id: str = typer.Argument(..., help="Policy ID to explain."),
    as_json: bool = typer.Option(False, "--as-json", help="Print explanation as JSON."),
) -> None:
    """Explain a policy and its remediation."""
    try:
        extras = (CUSTOM_POLICY_ROOT,) if CUSTOM_POLICY_ROOT.exists() else ()
        roots = resolve_policy_roots(BUILTIN_POLICY_ROOT, extras)
        policy = find_policy(policy_id, policy_roots=roots)
    except TerraGuardError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if policy is None:
        raise typer.BadParameter(f"Unknown policy ID: {policy_id}")

    why = policy.why or "This policy catches insecure Terraform before infrastructure is applied."
    remediation = (
        policy.remediation
        or "Review the matching Terraform resource and apply the remediation described in the policy."
    )
    fix = remediation_hcl(policy.policy_id)
    payload = {
        "policy_id": policy.policy_id,
        "title": policy.title,
        "severity": policy.severity,
        "resource": policy.resource,
        "controls": list(policy.controls),
        "why": why,
        "remediation": remediation,
        "fix_hcl": fix,
        "path": str(policy.path),
    }

    if as_json:
        typer.echo(json.dumps(payload, indent=2))
        return

    typer.echo(f"{policy.policy_id}: {policy.title}")
    typer.echo(f"Severity: {policy.severity}")
    typer.echo(f"Resource: {policy.resource}")
    if policy.controls:
        typer.echo(f"Controls: {', '.join(policy.controls)}")
    typer.echo("")
    typer.echo("Why it matters:")
    typer.echo(why)
    typer.echo("")
    typer.echo("How to fix:")
    typer.echo(remediation)
    if fix:
        typer.echo("")
        typer.echo("Suggested HCL:")
        typer.echo(fix)
