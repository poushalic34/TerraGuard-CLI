package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_eks_cluster"
	after := resource.change.after
	after.vpc_config[0].endpoint_public_access
	not after.vpc_config[0].endpoint_private_access

	finding := {
		"policy_id": "TG_AWS_EKS_011",
		"title": "EKS clusters with public endpoints should enable private access",
		"severity": "medium",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "EKS public endpoint is enabled while private endpoint access is disabled.",
		"remediation": "Enable endpoint_private_access and prefer private-only API access where possible.",
	}
}
