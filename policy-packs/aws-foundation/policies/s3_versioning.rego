package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_versioning"
	after := resource.change.after
	status := object.get(object.get(after, "versioning_configuration", [{}])[0], "status", "Disabled")
	lower(status) != "enabled"

	finding := {
		"policy_id": "TG_AWS_S3_002",
		"title": "S3 bucket versioning should be enabled",
		"severity": "medium",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "S3 bucket versioning is not enabled.",
		"remediation": "Set versioning_configuration status to Enabled.",
	}
}
