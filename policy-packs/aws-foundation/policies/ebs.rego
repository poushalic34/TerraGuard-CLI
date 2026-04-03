package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_ebs_volume"
	after := resource.change.after
	not after.encrypted

	finding := {
		"policy_id": "TG_AWS_EBS_001",
		"title": "EBS volumes must be encrypted",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "EBS volume encryption is disabled.",
		"remediation": "Set encrypted to true and use a customer-managed KMS key where required.",
	}
}

