import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from terraguard.exceptions import TerraformPlanError


def load_plan_json(plan_json: Path) -> dict[str, Any]:
    try:
        return json.loads(plan_json.read_text())
    except FileNotFoundError as exc:
        raise TerraformPlanError(f"Terraform plan JSON not found: {plan_json}") from exc
    except json.JSONDecodeError as exc:
        raise TerraformPlanError(f"Invalid Terraform plan JSON in {plan_json}: {exc}") from exc


def show_tfplan(tfplan: Path) -> dict[str, Any]:
    if not tfplan.exists():
        raise TerraformPlanError(f"Terraform plan file not found: {tfplan}")
    if shutil.which("terraform") is None:
        raise TerraformPlanError("terraform is not installed or not available on PATH.")

    completed = subprocess.run(
        ["terraform", "show", "-json", str(tfplan)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise TerraformPlanError(completed.stderr.strip() or "terraform show -json failed.")

    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise TerraformPlanError(f"terraform show returned invalid JSON: {exc}") from exc
