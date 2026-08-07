from pathlib import Path

from terraguard.config import TerraGuardConfig
from terraguard.constants import BUILTIN_POLICY_ROOT, CUSTOM_POLICY_ROOT
from terraguard.core.findings import Finding, ScanResult
from terraguard.core.opa import eval_deny_rules
from terraguard.core.plan_filter import filter_changed_resources
from terraguard.core.policy_loader import find_policy, policy_files, resolve_policy_roots
from terraguard.core.remediation import remediation_hcl
from terraguard.core.suppressions import apply_suppressions, load_suppressions
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

    plan = (
        show_tfplan(tfplan, binary=config.terraform_binary)
        if tfplan is not None
        else load_plan_json(plan_json)  # type: ignore[arg-type]
    )
    if config.changed_only:
        plan = filter_changed_resources(plan)

    roots = _policy_roots(config)
    results = eval_deny_rules(plan, policy_files(config.policy_packs, policy_roots=roots))
    findings = tuple(_enrich(Finding.from_opa_result(result), roots) for result in results)

    suppressions = load_suppressions(config.suppressions_path)
    active, suppressed, expired = apply_suppressions(findings, suppressions)
    expired_payload = tuple(
        {
            "policy_id": rule.policy_id,
            "resource": rule.resource,
            "expires": rule.expires.isoformat() if rule.expires else None,
            "owner": rule.owner,
            "ticket": rule.ticket,
            "reason": rule.reason,
        }
        for rule in expired
    )
    return ScanResult(
        findings=active,
        fail_on=config.fail_on,
        suppressed=suppressed,
        expired_suppressions=expired_payload,
    )


def _policy_roots(config: TerraGuardConfig) -> tuple[Path, ...]:
    extras = list(config.policy_dirs)
    if CUSTOM_POLICY_ROOT.exists():
        extras.append(CUSTOM_POLICY_ROOT)
    return resolve_policy_roots(BUILTIN_POLICY_ROOT, tuple(extras))


def _enrich(finding: Finding, roots: tuple[Path, ...]) -> Finding:
    policy = find_policy(finding.policy_id, policy_roots=roots)
    controls = finding.controls or (policy.controls if policy else ())
    fix = finding.fix_hcl or remediation_hcl(finding.policy_id)
    if controls == finding.controls and fix == finding.fix_hcl:
        return finding
    return Finding(
        policy_id=finding.policy_id,
        title=finding.title,
        severity=finding.severity,
        resource_type=finding.resource_type,
        resource_address=finding.resource_address,
        message=finding.message,
        remediation=finding.remediation,
        controls=controls,
        fix_hcl=fix,
    )
