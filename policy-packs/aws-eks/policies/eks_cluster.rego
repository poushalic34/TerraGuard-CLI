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
	count(after.enabled_cluster_log_types) == 0

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
	count(after.encryption_config) == 0

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

