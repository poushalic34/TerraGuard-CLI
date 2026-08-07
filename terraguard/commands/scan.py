from pathlib import Path

import typer
from rich.console import Console

from terraguard.config import apply_overrides, load_config
from terraguard.core.scanner import scan_plan
from terraguard.exceptions import TerraGuardError
from terraguard.output import console as console_output
from terraguard.output import html, json, markdown, sarif

app = typer.Typer(no_args_is_help=False)
console = Console()


@app.callback(invoke_without_command=True)
def command(
    tfplan: Path | None = typer.Option(None, "--tfplan", help="Terraform/OpenTofu binary plan file."),
    plan_json: Path | None = typer.Option(None, "--plan-json", help="Terraform plan JSON file."),
    config: Path | None = typer.Option(None, "--config", help="Path to .terraguard.yml."),
    policy_pack: list[str] | None = typer.Option(
        None,
        "--policy-pack",
        help="Policy pack to evaluate. Repeatable. Overrides config when set.",
    ),
    policy_dir: list[Path] | None = typer.Option(
        None,
        "--policy-dir",
        help="Additional policy pack directory. Repeatable.",
    ),
    suppressions: Path | None = typer.Option(
        None,
        "--suppressions",
        help="Path to .terraguard-ignore.yml suppressions file.",
    ),
    changed_only: bool = typer.Option(
        False,
        "--changed-only",
        help="Only evaluate resources with create/update/delete/replace actions.",
    ),
    terraform_binary: str | None = typer.Option(
        None,
        "--terraform-binary",
        help="Binary used for show -json (terraform or tofu).",
    ),
    output_format: str | None = typer.Option(
        None, "--format", help="console, json, markdown, html, sarif."
    ),
    output: Path | None = typer.Option(None, "--output", help="Write scan output to a file."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Minimum severity that fails the scan."),
) -> None:
    """Scan a Terraform plan against OPA/Rego policy packs."""
    try:
        loaded = load_config(config)
        loaded = apply_overrides(
            loaded,
            policy_packs=tuple(policy_pack) if policy_pack else None,
            fail_on=fail_on,
            output_format=output_format,
            output_path=str(output) if output is not None else None,
            policy_dirs=tuple(policy_dir) if policy_dir else None,
            suppressions_path=suppressions,
            changed_only=changed_only or None,
            terraform_binary=terraform_binary,
        )
        # apply_overrides treats False specially; force changed_only from flag/config
        if changed_only:
            loaded = apply_overrides(loaded, changed_only=True)

        result = scan_plan(loaded, tfplan=tfplan, plan_json=plan_json)
        fmt = loaded.output_format
        rendered = _render(fmt, result)

        if output:
            output.write_text(rendered if isinstance(rendered, str) else json.render(result))
        elif isinstance(rendered, str):
            typer.echo(rendered)
        else:
            console.print(rendered)

        if result.expired_suppressions:
            console.print(
                f"[yellow]Warning:[/yellow] {len(result.expired_suppressions)} expired suppression(s)."
            )
        if result.suppressed:
            console.print(f"[dim]Suppressed findings: {len(result.suppressed)}[/dim]")
    except TerraGuardError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    raise typer.Exit(code=1 if result.failed else 0)


def _render(fmt: str, result):
    if fmt == "console":
        return console_output.render(result)
    if fmt == "json":
        return json.render(result)
    if fmt == "markdown":
        return markdown.render(result)
    if fmt == "html":
        return html.render(result)
    if fmt == "sarif":
        return sarif.render(result)
    raise typer.BadParameter(f"Unknown output format: {fmt}")
