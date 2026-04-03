import json as json_lib
from pathlib import Path

import typer

from terraguard.core.findings import Finding, ScanResult
from terraguard.output import html, json, markdown, sarif

app = typer.Typer(no_args_is_help=False)


@app.callback(invoke_without_command=True)
def command(
    input: Path = typer.Option(..., "--input", help="Scan result JSON file."),
    output_format: str = typer.Option("markdown", "--format", help="markdown, html, json, sarif."),
    output: Path | None = typer.Option(None, "--output", help="Write report to a file."),
) -> None:
    """Render a report from scan results."""
    data = json_lib.loads(input.read_text())
    result = ScanResult(
        findings=tuple(Finding.from_opa_result(item) for item in data.get("findings", [])),
        fail_on=str(data.get("fail_on", "high")),
    )
    rendered = _render(output_format, result)
    if output:
        output.write_text(rendered)
    else:
        typer.echo(rendered)


def _render(fmt: str, result: ScanResult) -> str:
    if fmt == "json":
        return json.render(result)
    if fmt == "markdown":
        return markdown.render(result)
    if fmt == "html":
        return html.render(result)
    if fmt == "sarif":
        return sarif.render(result)
    raise typer.BadParameter(f"Unknown report format: {fmt}")

