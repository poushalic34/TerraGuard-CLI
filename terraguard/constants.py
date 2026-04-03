from pathlib import Path

APP_NAME = "terraguard"
CONFIG_FILE = ".terraguard.yml"
DEFAULT_FAIL_ON = "high"
DEFAULT_POLICY_PACKS = ("aws-foundation", "aws-eks")
SEVERITIES = ("info", "low", "medium", "high", "critical")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUILTIN_POLICY_ROOT = PROJECT_ROOT / "policy-packs"

