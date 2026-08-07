package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_eks_cluster"
	after := resource.change.after
	after.vpc_config[0].endpoint_public_access

	finding := {
		"policy_id": "TG_AWS_EKS_001",
		"title": "EKS public endpoint access must be restricted",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "EKS cluster public endpoint access is enabled.",
		"remediation": "Disable public endpoint access or restrict public_access_cidrs to approved networks.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_eks_cluster"
	after := resource.change.after
	not has_cluster_logs(after)

	finding := {
		"policy_id": "TG_AWS_EKS_002",
		"title": "EKS control plane logging must be enabled",
		"severity": "medium",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "EKS control plane logging is not enabled.",
		"remediation": "Enable API, audit, authenticator, controllerManager, and scheduler logs as appropriate.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_eks_cluster"
	after := resource.change.after
	not has_secrets_encryption(after)

	finding := {
		"policy_id": "TG_AWS_EKS_003",
		"title": "EKS secrets encryption should use KMS",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "EKS cluster secrets encryption is not configured.",
		"remediation": "Configure encryption_config with a customer-managed KMS key for Kubernetes secrets.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_eks_cluster"
	after := resource.change.after
	after.vpc_config[0].endpoint_public_access
	cidrs := object.get(after.vpc_config[0], "public_access_cidrs", [])
	cidrs != null
	cidrs[_] == "0.0.0.0/0"

	finding := {
		"policy_id": "TG_AWS_EKS_005",
		"title": "EKS public endpoint CIDRs must not be open to the world",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "EKS public_access_cidrs includes 0.0.0.0/0.",
		"remediation": "Restrict public_access_cidrs to trusted networks or disable public endpoint access.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_eks_cluster"
	after := resource.change.after
	has_cluster_logs(after)
	not required_log_enabled(after, "audit")

	finding := {
		"policy_id": "TG_AWS_EKS_006",
		"title": "EKS audit logging must be enabled",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "EKS control plane audit logs are not enabled.",
		"remediation": "Include audit in enabled_cluster_log_types.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_eks_cluster"
	after := resource.change.after
	has_cluster_logs(after)
	not required_log_enabled(after, "authenticator")

	finding := {
		"policy_id": "TG_AWS_EKS_007",
		"title": "EKS authenticator logging must be enabled",
		"severity": "medium",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "EKS authenticator logs are not enabled.",
		"remediation": "Include authenticator in enabled_cluster_log_types.",
	}
}

has_cluster_logs(after) if {
	count(after.enabled_cluster_log_types) > 0
}

has_secrets_encryption(after) if {
	count(after.encryption_config) > 0
}

required_log_enabled(after, name) if {
	after.enabled_cluster_log_types[_] == name
}
