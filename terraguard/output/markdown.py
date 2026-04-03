from terraguard.core.findings import ScanResult


def render(result: ScanResult) -> str:
    lines = [
        "# TerraGuard Report",
        "",
        f"- Failed: `{str(result.failed).lower()}`",
        f"- Failure threshold: `{result.fail_on}`",
        f"- Total findings: `{len(result.findings)}`",
        "",
        "## Findings",
        "",
    ]

    if not result.findings:
        lines.append("No policy violations found.")
        return "\n".join(lines)

    for finding in result.findings:
        lines.extend(
            [
                f"### {finding.policy_id}: {finding.title}",
                "",
                f"- Severity: `{finding.severity}`",
                f"- Resource: `{finding.resource_address}`",
                f"- Resource type: `{finding.resource_type}`",
                f"- Message: {finding.message}",
                f"- Remediation: {finding.remediation}",
                "",
            ]
        )

    return "\n".join(lines)

