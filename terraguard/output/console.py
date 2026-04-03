from rich.table import Table

from terraguard.core.findings import ScanResult


def render(result: ScanResult) -> Table:
    table = Table(title="TerraGuard Findings")
    table.add_column("Severity")
    table.add_column("Policy")
    table.add_column("Resource")
    table.add_column("Message")

    for finding in result.findings:
        table.add_row(
            finding.severity.upper(),
            finding.policy_id,
            finding.resource_address,
            finding.message,
        )

    if not result.findings:
        table.add_row("PASS", "-", "-", "No policy violations found.")

    return table

