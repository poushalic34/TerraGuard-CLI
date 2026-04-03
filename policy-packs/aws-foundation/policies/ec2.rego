package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_instance"
	after := resource.change.after
	after.metadata_options.http_tokens != "required"

	finding := {
		"policy_id": "TG_AWS_EC2_001",
		"title": "EC2 instances must require IMDSv2",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "EC2 metadata options do not require IMDSv2 tokens.",
		"remediation": "Set metadata_options.http_tokens to required on the aws_instance resource.",
	}
}

