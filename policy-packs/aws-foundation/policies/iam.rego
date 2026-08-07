package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_iam_policy"
	after := resource.change.after
	contains(after.policy, "\"Action\":\"*\"")
	contains(after.policy, "\"Resource\":\"*\"")

	finding := {
		"policy_id": "TG_AWS_IAM_001",
		"title": "IAM policies should avoid wildcard admin permissions",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "IAM policy appears to allow wildcard actions on wildcard resources.",
		"remediation": "Replace wildcard permissions with least-privilege actions and scoped resources.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_iam_role"
	after := resource.change.after
	contains(after.assume_role_policy, "\"Principal\"")
	contains(after.assume_role_policy, "\"AWS\":\"*\"")

	finding := {
		"policy_id": "TG_AWS_IAM_002",
		"title": "IAM role trust policies must not allow all AWS principals",
		"severity": "critical",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "IAM role trust policy allows Principal AWS=*.",
		"remediation": "Scope the trust policy principal to specific account roles or services.",
	}
}
