package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_db_instance"
	after := resource.change.after
	not after.storage_encrypted

	finding := {
		"policy_id": "TG_AWS_RDS_001",
		"title": "RDS storage must be encrypted",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "RDS instance storage encryption is disabled.",
		"remediation": "Set storage_encrypted to true and provide a KMS key when required.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_db_instance"
	after := resource.change.after
	after.publicly_accessible

	finding := {
		"policy_id": "TG_AWS_RDS_002",
		"title": "RDS instances must not be publicly accessible",
		"severity": "critical",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "RDS instance is publicly accessible.",
		"remediation": "Set publicly_accessible to false and place the instance in private subnets.",
	}
}
