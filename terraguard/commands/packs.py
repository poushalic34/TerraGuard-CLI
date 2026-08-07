import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import typer
from rich.console import Console

from terraguard.constants import CUSTOM_POLICY_ROOT
from terraguard.exceptions import PolicyError

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("add")
def add(
    source: str = typer.Argument(..., help="Local path or git URL to a policy packs root or pack."),
    name: str | None = typer.Option(None, "--name", help="Destination pack folder name."),
) -> None:
    """Install a custom policy pack into .terraguard/packs."""
    CUSTOM_POLICY_ROOT.mkdir(parents=True, exist_ok=True)
    source_path = Path(source)
    if source_path.exists():
        _install_from_path(source_path, name)
        return
    if _looks_like_git(source):
        _install_from_git(source, name)
        return
    raise PolicyError(f"Source is neither a local path nor a git URL: {source}")


@app.command("list")
def list_packs() -> None:
    """List installed custom packs under .terraguard/packs."""
    if not CUSTOM_POLICY_ROOT.exists():
        console.print("No custom packs installed.")
        return
    packs = sorted(path for path in CUSTOM_POLICY_ROOT.iterdir() if path.is_dir())
    if not packs:
        console.print("No custom packs installed.")
        return
    for pack in packs:
        console.print(str(pack))


def _install_from_path(source_path: Path, name: str | None) -> None:
    pack_dir = _resolve_pack_dir(source_path)
    dest_name = name or pack_dir.name
    dest = CUSTOM_POLICY_ROOT / dest_name
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(pack_dir, dest)
    console.print(f"Installed pack '{dest_name}' from {pack_dir} -> {dest}")


def _install_from_git(url: str, name: str | None) -> None:
    if shutil.which("git") is None:
        raise PolicyError("git is required to install packs from a URL.")
    dest_name = name or _default_git_name(url)
    dest = CUSTOM_POLICY_ROOT / dest_name
    staging = CUSTOM_POLICY_ROOT / f".staging-{dest_name}"
    if staging.exists():
        shutil.rmtree(staging)
    completed = subprocess.run(
        ["git", "clone", "--depth", "1", url, str(staging)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise PolicyError(completed.stderr.strip() or f"git clone failed for {url}")
    try:
        pack_dir = _resolve_pack_dir(staging)
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(pack_dir, dest)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    console.print(f"Installed pack '{dest_name}' from {url} -> {dest}")


def _resolve_pack_dir(path: Path) -> Path:
    if (path / "pack.yml").exists():
        return path
    # Allow pointing at a root that contains one pack directory.
    children = [child for child in path.iterdir() if child.is_dir() and (child / "pack.yml").exists()]
    if len(children) == 1:
        return children[0]
    if (path / "policy-packs").exists():
        nested = [
            child
            for child in (path / "policy-packs").iterdir()
            if child.is_dir() and (child / "pack.yml").exists()
        ]
        if len(nested) == 1:
            return nested[0]
    raise PolicyError(
        f"Could not find pack.yml under {path}. Point at a pack directory or a root with one pack."
    )


def _looks_like_git(source: str) -> bool:
    if source.startswith("git@"):
        return True
    parsed = urlparse(source)
    return parsed.scheme in {"http", "https", "ssh"} and bool(parsed.netloc)


def _default_git_name(url: str) -> str:
    path = urlparse(url).path if "://" in url else url.rsplit(":", 1)[-1]
    name = Path(path.rstrip("/")).stem
    return name or "custom-pack"
