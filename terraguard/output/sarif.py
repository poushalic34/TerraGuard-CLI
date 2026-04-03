import json

from terraguard.core.findings import ScanResult


def render(result: ScanResult) -> str:
    rules = []
    results = []
    for finding in result.findings:
        rules.append(
            {
                "id": finding.policy_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation},
            }
        )
        results.append(
            {
                "ruleId": finding.policy_id,
                "level": _level(finding.severity),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.resource_address}
                        }
                    }
                ],
            }
        )

    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TerraGuard CLI",
                            "informationUri": "https://github.com/poushalic34/TerraGuard-CLI",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        },
        indent=2,
    )


def _level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"

