package terraguard

import rego.v1

test_kms_rotation_disabled_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_kms_key.norotation",
		"type": "aws_kms_key",
		"change": {"after": {"enable_key_rotation": false}},
	}]}
	count(result) == 1
	some finding in result
	finding.policy_id == "TG_AWS_KMS_001"
}

test_kms_rotation_enabled_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_kms_key.secure",
		"type": "aws_kms_key",
		"change": {"after": {"enable_key_rotation": true}},
	}]}
	not kms_findings(result)
}

kms_findings(result) if {
	some finding in result
	finding.policy_id == "TG_AWS_KMS_001"
}
