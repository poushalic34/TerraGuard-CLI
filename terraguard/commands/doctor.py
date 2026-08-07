import json
import shutil
import subprocess
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from terraguard.config import load_config
from terraguard.constants import CONFIG_FILE, CUSTOM_POLICY_ROOT
from terraguard.core.policy_loader import list_policy_packs, load_policy_pack
from terraguard.core.suppressions import load_suppressions
from terraguard.core.terraform import PLAN_BINARIES
from terraguard.exceptions import TerraGuardError

app = typer.Typer(no_args_is_help=False)
console = Console()


@app.callback(invoke_without_command=True)
def command(
    as_json: bool = typer.Option(False, "--as-json", help="Print machine-readable diagnostics."),
) -> None:
    """Check local dependencies and project readiness."""
    checks: list[dict[str, str]] = []
    failed = False

    for binary in PLAN_BINARIES:
        check = _binary_check(binary, required=False)
        checks.append(check)
    if not any(check["status"] == "ok" and check["check"] in PLAN_BINARIES for check in checks):
        failed = True
        checks.append(
            {
                "check": "plan-binary",
                "status": "missing",
                "details": "Need terraform or tofu on PATH",
            }
        )

    opa_check = _binary_check("opa", required=True)
    checks.append(opa_check)
    if opa_check["status"] != "ok":
        failed = True

    config_check = _config_check()
    checks.append(config_check)
    if config_check["status"] == "error":
        failed = True

    packs_check = _policy_packs_check()
    checks.append(packs_check)
    if packs_check["status"] == "error":
        failed = True

    suppressions_check = _suppressions_check()
    checks.append(suppressions_check)
    if suppressions_check["status"] == "error":
        failed = True

    if as_json:
        typer.echo(json.dumps({"ok": not failed, "checks": checks}, indent=2))
    else:
        table = Table(title="TerraGuard Doctor")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Details")
        for check in checks:
            table.add_row(check["check"], check["status"], check["details"])
        console.print(table)

    if failed:
        raise typer.Exit(code=1)


def _binary_check(binary: str, *, required: bool) -> dict[str, str]:
    path = shutil.which(binary)
    if path is None:
        status = "missing" if required else "warn"
        return {"check": binary, "status": status, "details": f"{binary} not found on PATH"}

    completed = subprocess.run([binary, "version"], check=False, capture_output=True, text=True)
    detail = completed.stdout.splitlines()[0] if completed.stdout else path
    return {"check": binary, "status": "ok", "details": detail}


def _config_check() -> dict[str, str]:
    if not Path(CONFIG_FILE).exists():
        return {
            "check": "config",
            "status": "warn",
            "details": f"{CONFIG_FILE} not found; defaults will be used",
        }

    try:
        config = load_config()
    except TerraGuardError as exc:
        return {"check": "config", "status": "error", "details": str(exc)}

    return {
        "check": "config",
        "status": "ok",
        "details": f"{CONFIG_FILE}: packs={', '.join(config.policy_packs)}",
    }


def _policy_packs_check() -> dict[str, str]:
    try:
        config = load_config() if Path(CONFIG_FILE).exists() else None
        if config:
            pack_names = config.policy_packs
            for name in pack_names:
                # Prefer builtin; custom packs live under CUSTOM_POLICY_ROOT
                try:
                    load_policy_pack(name)
                except TerraGuardError:
                    load_policy_pack(name, CUSTOM_POLICY_ROOT)
        else:
            pack_names = tuple(pack.name for pack in list_policy_packs())
            for name in pack_names:
                load_policy_pack(name)
    except TerraGuardError as exc:
        return {"check": "policy-packs", "status": "error", "details": str(exc)}

    return {
        "check": "policy-packs",
        "status": "ok",
        "details": f"{len(pack_names)} pack(s) available",
    }


def _suppressions_check() -> dict[str, str]:
    path = Path(".terraguard-ignore.yml")
    if not path.exists():
        return {"check": "suppressions", "status": "warn", "details": "no suppressions file"}
    try:
        rules = load_suppressions(path)
    except TerraGuardError as exc:
        return {"check": "suppressions", "status": "error", "details": str(exc)}
    return {
        "check": "suppressions",
        "status": "ok",
        "details": f"{len(rules)} suppression rule(s)",
    }
