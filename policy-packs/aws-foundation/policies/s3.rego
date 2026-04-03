package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_public_access_block"
	after := resource.change.after
	not after.block_public_acls

	finding := {
		"policy_id": "TG_AWS_S3_001",
		"title": "S3 public access block must be enabled",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "S3 bucket public ACL blocking is disabled.",
		"remediation": "Enable block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_public_access_block"
	after := resource.change.after
	not after.block_public_policy

	finding := {
		"policy_id": "TG_AWS_S3_001",
		"title": "S3 public access block must be enabled",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "S3 bucket public policy blocking is disabled.",
		"remediation": "Enable block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets.",
	}
}

