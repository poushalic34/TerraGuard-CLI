import json as json_lib
from pathlib import Path

import typer

from terraguard.core.findings import Finding, ScanResult
from terraguard.exceptions import TerraGuardError
from terraguard.output import pr_comment

app = typer.Typer(no_args_is_help=False)


@app.callback(invoke_without_command=True)
def command(
    input: Path = typer.Option(..., "--input", help="Scan result JSON file."),
    output: Path | None = typer.Option(None, "--output", help="Write comment markdown to a file."),
    title: str = typer.Option("TerraGuard Policy Scan", "--title", help="Comment heading."),
    post: bool = typer.Option(
        False,
        "--post",
        help="Create or update a sticky PR comment using GITHUB_TOKEN.",
    ),
    pr: int | None = typer.Option(None, "--pr", help="Pull request number (defaults from event)."),
    repository: str | None = typer.Option(
        None, "--repository", help="owner/repo (defaults to GITHUB_REPOSITORY)."
    ),
) -> None:
    """Render a sticky GitHub PR comment from scan results."""
    try:
        result = _load_result(input)
        body = pr_comment.render(result, title=title)

        if output:
            output.write_text(body)
        else:
            typer.echo(body)

        if post:
            response = pr_comment.post_or_update_comment(
                body,
                repository=repository,
                pr_number=pr,
            )
            html_url = response.get("html_url", "")
            typer.echo(
                f"Sticky PR comment ready{': ' + html_url if html_url else '.'}",
                err=True,
            )
    except TerraGuardError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _load_result(path: Path) -> ScanResult:
    data = json_lib.loads(path.read_text())
    return ScanResult(
        findings=tuple(Finding.from_opa_result(item) for item in data.get("findings", [])),
        fail_on=str(data.get("fail_on", "high")),
        suppressed=tuple(Finding.from_opa_result(item) for item in data.get("suppressed", [])),
        expired_suppressions=tuple(data.get("expired_suppressions") or ()),
        schema_version=str(data.get("schema_version", "1.0.0")),
    )
