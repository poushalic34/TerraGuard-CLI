from dataclasses import asdict, dataclass
from typing import Any

from terraguard.core.severity import meets_threshold

FINDINGS_SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class Finding:
    policy_id: str
    title: str
    severity: str
    resource_type: str
    resource_address: str
    message: str
    remediation: str
    controls: tuple[str, ...] = ()
    fix_hcl: str | None = None

    @classmethod
    def from_opa_result(cls, data: dict[str, Any]) -> "Finding":
        controls = data.get("controls") or ()
        if isinstance(controls, str):
            controls = (controls,)
        return cls(
            policy_id=str(data.get("policy_id", "TG_UNKNOWN")),
            title=str(data.get("title", "Policy violation")),
            severity=str(data.get("severity", "medium")).lower(),
            resource_type=str(data.get("resource_type", "unknown")),
            resource_address=str(data.get("resource_address", "unknown")),
            message=str(data.get("message", "Policy violation detected.")),
            remediation=str(
                data.get("remediation", "Review the policy and update the Terraform code.")
            ),
            controls=tuple(str(item) for item in controls),
            fix_hcl=data.get("fix_hcl"),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["controls"] = list(self.controls)
        return payload


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    fail_on: str
    suppressed: tuple[Finding, ...] = ()
    expired_suppressions: tuple[dict[str, Any], ...] = ()
    schema_version: str = FINDINGS_SCHEMA_VERSION

    @property
    def failed(self) -> bool:
        if self.expired_suppressions:
            return True
        return any(meets_threshold(finding.severity, self.fail_on) for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "failed": self.failed,
            "fail_on": self.fail_on,
            "summary": {
                "total": len(self.findings),
                "critical": _count(self.findings, "critical"),
                "high": _count(self.findings, "high"),
                "medium": _count(self.findings, "medium"),
                "low": _count(self.findings, "low"),
                "info": _count(self.findings, "info"),
                "suppressed": len(self.suppressed),
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "suppressed": [finding.to_dict() for finding in self.suppressed],
            "expired_suppressions": list(self.expired_suppressions),
        }


def _count(findings: tuple[Finding, ...], severity: str) -> int:
    return sum(1 for finding in findings if finding.severity == severity)
