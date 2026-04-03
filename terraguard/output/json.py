import json

from terraguard.core.findings import ScanResult


def render(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)

