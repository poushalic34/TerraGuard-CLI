import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from terraguard.exceptions import TerraformPlanError

PLAN_BINARIES = ("terraform", "tofu")


def load_plan_json(plan_json: Path) -> dict[str, Any]:
    try:
        return json.loads(plan_json.read_text())
    except FileNotFoundError as exc:
        raise TerraformPlanError(f"Terraform plan JSON not found: {plan_json}") from exc
    except json.JSONDecodeError as exc:
        raise TerraformPlanError(f"Invalid Terraform plan JSON in {plan_json}: {exc}") from exc


def show_tfplan(tfplan: Path, binary: str | None = None) -> dict[str, Any]:
    if not tfplan.exists():
        raise TerraformPlanError(f"Terraform plan file not found: {tfplan}")

    plan_binary = binary or detect_plan_binary()
    completed = subprocess.run(
        [plan_binary, "show", "-json", str(tfplan)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise TerraformPlanError(
            completed.stderr.strip() or f"{plan_binary} show -json failed."
        )

    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise TerraformPlanError(f"{plan_binary} show returned invalid JSON: {exc}") from exc


def detect_plan_binary() -> str:
    for binary in PLAN_BINARIES:
        if shutil.which(binary) is not None:
            return binary
    raise TerraformPlanError(
        "Neither terraform nor tofu is installed or available on PATH."
    )
