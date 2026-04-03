package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_kms_key"
	after := resource.change.after
	not after.enable_key_rotation

	finding := {
		"policy_id": "TG_AWS_KMS_001",
		"title": "KMS key rotation must be enabled",
		"severity": "medium",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "KMS key rotation is disabled.",
		"remediation": "Set enable_key_rotation to true for customer-managed KMS keys.",
	}
}

