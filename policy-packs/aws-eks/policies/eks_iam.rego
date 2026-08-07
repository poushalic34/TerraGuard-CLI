package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_iam_role"
	after := resource.change.after
	contains(after.assume_role_policy, "oidc.eks")
	contains(after.assume_role_policy, "\"Action\":\"*\"")

	finding := {
		"policy_id": "TG_AWS_EKS_010",
		"title": "EKS IRSA roles must not allow wildcard actions in trust",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "IRSA trust policy appears to allow wildcard actions.",
		"remediation": "Limit IRSA trust to sts:AssumeRoleWithWebIdentity for the specific OIDC subject.",
	}
}
