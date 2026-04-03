class TerraGuardError(Exception):
    """Base exception for user-facing TerraGuard failures."""


class ConfigError(TerraGuardError):
    """Raised when TerraGuard configuration is invalid."""


class DependencyError(TerraGuardError):
    """Raised when a required local dependency is missing."""


class PolicyError(TerraGuardError):
    """Raised when policy loading or validation fails."""


class TerraformPlanError(TerraGuardError):
    """Raised when Terraform plan input cannot be read or converted."""

