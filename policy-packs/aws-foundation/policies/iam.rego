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

