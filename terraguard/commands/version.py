import platform

import typer

from terraguard import __version__

app = typer.Typer(no_args_is_help=False)


@app.callback(invoke_without_command=True)
def command() -> None:
    """Print TerraGuard version information."""
    typer.echo(f"TerraGuard CLI {__version__}")
    typer.echo(f"Python {platform.python_version()}")

