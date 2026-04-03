import shutil
import subprocess
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from terraguard.config import load_config
from terraguard.constants import CONFIG_FILE

app = typer.Typer(no_args_is_help=False)
console = Console()


@app.callback(invoke_without_command=True)
def command() -> None:
    """Check local dependencies and project readiness."""
    table = Table(title="TerraGuard Doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Details")

    _add_binary_check(table, "terraform")
    _add_binary_check(table, "opa")

    if Path(CONFIG_FILE).exists():
        try:
            config = load_config()
            table.add_row("config", "ok", f"{CONFIG_FILE}: packs={', '.join(config.policy_packs)}")
        except Exception as exc:  # noqa: BLE001
            table.add_row("config", "error", str(exc))
    else:
        table.add_row("config", "warn", f"{CONFIG_FILE} not found; defaults will be used")

    console.print(table)


def _add_binary_check(table: Table, binary: str) -> None:
    path = shutil.which(binary)
    if path is None:
        table.add_row(binary, "missing", f"{binary} not found on PATH")
        return

    completed = subprocess.run([binary, "version"], check=False, capture_output=True, text=True)
    detail = completed.stdout.splitlines()[0] if completed.stdout else path
    table.add_row(binary, "ok", detail)

