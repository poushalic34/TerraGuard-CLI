from pathlib import Path

from terraguard.config import TerraGuardConfig
from terraguard.core.findings import Finding, ScanResult
from terraguard.core.opa import eval_deny_rules
from terraguard.core.policy_loader import policy_files
from terraguard.core.terraform import load_plan_json, show_tfplan
from terraguard.exceptions import TerraformPlanError


def scan_plan(
    config: TerraGuardConfig,
    tfplan: Path | None = None,
    plan_json: Path | None = None,
) -> ScanResult:
    if tfplan is None and plan_json is None:
        raise TerraformPlanError("Provide either --tfplan or --plan-json.")
    if tfplan is not None and plan_json is not None:
        raise TerraformPlanError("Use only one of --tfplan or --plan-json.")

    plan = show_tfplan(tfplan) if tfplan is not None else load_plan_json(plan_json)  # type: ignore[arg-type]
    results = eval_deny_rules(plan, policy_files(config.policy_packs))
    findings = tuple(Finding.from_opa_result(result) for result in results)
    return ScanResult(findings=findings, fail_on=config.fail_on)

