import json
from pathlib import Path

import pytest

from terraguard.core.terraform import load_plan_json
from terraguard.exceptions import TerraformPlanError


def test_load_plan_json(tmp_path: Path) -> None:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({"resource_changes": []}))

    assert load_plan_json(path) == {"resource_changes": []}


def test_load_plan_json_missing() -> None:
    with pytest.raises(TerraformPlanError, match="not found"):
        load_plan_json(Path("/tmp/does-not-exist-terraguard.json"))


def test_load_plan_json_invalid(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not-json")

    with pytest.raises(TerraformPlanError, match="Invalid Terraform plan JSON"):
        load_plan_json(path)
