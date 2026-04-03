from pathlib import Path

import typer
from rich.console import Console

from terraguard.config import load_config
from terraguard.core.scanner import scan_plan
from terraguard.output import console as console_output
from terraguard.output import html, json, markdown, sarif

app = typer.Typer(no_args_is_help=False)
console = Console()


@app.callback(invoke_without_command=True)
def command(
    tfplan: Path | None = typer.Option(None, "--tfplan", help="Terraform binary plan file."),
    plan_json: Path | None = typer.Option(None, "--plan-json", help="Terraform plan JSON file."),
    config: Path | None = typer.Option(None, "--config", help="Path to .terraguard.yml."),
    output_format: str | None = typer.Option(None, "--format", help="console, json, markdown, html, sarif."),
    output: Path | None = typer.Option(None, "--output", help="Write scan output to a file."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Minimum severity that fails the scan."),
) -> None:
    """Scan a Terraform plan against OPA/Rego policy packs."""
    loaded = load_config(config)
    if fail_on:
        loaded = loaded.__class__(
            policy_packs=loaded.policy_packs,
            fail_on=fail_on,
            output_format=loaded.output_format,
            output_path=loaded.output_path,
        )
    result = scan_plan(loaded, tfplan=tfplan, plan_json=plan_json)
    fmt = output_format or loaded.output_format
    rendered = _render(fmt, result)

    if output:
        output.write_text(rendered if isinstance(rendered, str) else json.render(result))
    elif isinstance(rendered, str):
        typer.echo(rendered)
    else:
        console.print(rendered)

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

