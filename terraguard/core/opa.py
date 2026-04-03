import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from terraguard.exceptions import PolicyError


def validate_rego(policy_files: tuple[Path, ...]) -> None:
    _require_opa()
    for policy_file in policy_files:
        completed = subprocess.run(
            ["opa", "fmt", "--diff", str(policy_file)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode not in (0, 1):
            raise PolicyError(completed.stderr.strip() or f"OPA could not parse {policy_file}.")


def eval_deny_rules(plan: dict[str, Any], policy_files: tuple[Path, ...]) -> list[dict[str, Any]]:
    _require_opa()
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as input_file:
        json.dump(plan, input_file)
        input_path = Path(input_file.name)

    cmd = ["opa", "eval", "--format", "json", "--input", str(input_path)]
    for policy_file in policy_files:
        cmd.extend(["--data", str(policy_file)])
    cmd.append("data.terraguard.deny")

    completed = subprocess.run(cmd, check=False, capture_output=True, text=True)
    input_path.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise PolicyError(completed.stderr.strip() or "OPA evaluation failed.")

    payload = json.loads(completed.stdout)
    expressions = payload.get("result", [{}])[0].get("expressions", [])
    if not expressions:
        return []

    value = expressions[0].get("value", [])
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _require_opa() -> None:
    if shutil.which("opa") is None:
        raise PolicyError("opa is not installed or not available on PATH. Install OPA before scanning.")
