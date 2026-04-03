from terraguard.constants import SEVERITIES
from terraguard.exceptions import ConfigError


def severity_rank(severity: str) -> int:
    normalized = severity.lower()
    if normalized not in SEVERITIES:
        raise ConfigError(f"Unknown severity '{severity}'. Expected one of: {', '.join(SEVERITIES)}.")
    return SEVERITIES.index(normalized)


def meets_threshold(severity: str, threshold: str) -> bool:
    return severity_rank(severity) >= severity_rank(threshold)

