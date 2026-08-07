package terraguard

import rego.v1

test_s3_public_access_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.public",
		"type": "aws_s3_bucket_public_access_block",
		"change": {"after": {
			"block_public_acls": false,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		}},
	}]}
	count(result) == 1
	some finding in result
	finding.policy_id == "TG_AWS_S3_001"
}

test_s3_secure_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.secure",
		"type": "aws_s3_bucket_public_access_block",
		"change": {"after": {
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		}},
	}]}
	not s3_findings(result)
}

test_s3_versioning_disabled_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_s3_bucket_versioning.disabled",
		"type": "aws_s3_bucket_versioning",
		"change": {"after": {"versioning_configuration": [{"status": "Disabled"}]}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_S3_002"]) == 1
}

test_s3_versioning_enabled_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_s3_bucket_versioning.enabled",
		"type": "aws_s3_bucket_versioning",
		"change": {"after": {"versioning_configuration": [{"status": "Enabled"}]}},
	}]}
	not s3_versioning_findings(result)
}

s3_findings(result) if {
	some finding in result
	finding.policy_id == "TG_AWS_S3_001"
}

s3_versioning_findings(result) if {
	some finding in result
	finding.policy_id == "TG_AWS_S3_002"
}
