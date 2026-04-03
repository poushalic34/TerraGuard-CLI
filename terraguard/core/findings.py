from dataclasses import asdict, dataclass
from typing import Any

from terraguard.core.severity import meets_threshold


@dataclass(frozen=True)
class Finding:
    policy_id: str
    title: str
    severity: str
    resource_type: str
    resource_address: str
    message: str
    remediation: str

    @classmethod
    def from_opa_result(cls, data: dict[str, Any]) -> "Finding":
        return cls(
            policy_id=str(data.get("policy_id", "TG_UNKNOWN")),
            title=str(data.get("title", "Policy violation")),
            severity=str(data.get("severity", "medium")).lower(),
            resource_type=str(data.get("resource_type", "unknown")),
            resource_address=str(data.get("resource_address", "unknown")),
            message=str(data.get("message", "Policy violation detected.")),
            remediation=str(data.get("remediation", "Review the policy and update the Terraform code.")),
        )

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    fail_on: str

    @property
    def failed(self) -> bool:
        return any(meets_threshold(finding.severity, self.fail_on) for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "failed": self.failed,
            "fail_on": self.fail_on,
            "summary": {
                "total": len(self.findings),
                "critical": _count(self.findings, "critical"),
                "high": _count(self.findings, "high"),
                "medium": _count(self.findings, "medium"),
                "low": _count(self.findings, "low"),
                "info": _count(self.findings, "info"),
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _count(findings: tuple[Finding, ...], severity: str) -> int:
    return sum(1 for finding in findings if finding.severity == severity)

