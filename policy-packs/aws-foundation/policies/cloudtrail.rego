package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_cloudtrail"
	after := resource.change.after
	not after.is_multi_region_trail

	finding := {
		"policy_id": "TG_AWS_CT_001",
		"title": "CloudTrail must be multi-region",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "CloudTrail is not configured as a multi-region trail.",
		"remediation": "Set is_multi_region_trail to true and enable log file validation.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_cloudtrail"
	after := resource.change.after
	not after.enable_log_file_validation

	finding := {
		"policy_id": "TG_AWS_CT_002",
		"title": "CloudTrail log file validation must be enabled",
		"severity": "medium",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "CloudTrail log file validation is disabled.",
		"remediation": "Set enable_log_file_validation to true.",
	}
}
