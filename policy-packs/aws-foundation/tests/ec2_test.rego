package terraguard

import rego.v1

test_ec2_imdsv1_array_metadata_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_instance.legacy",
		"type": "aws_instance",
		"change": {"after": {"metadata_options": [{"http_tokens": "optional"}]}},
	}]}
	count(result) == 1
	some finding in result
	finding.policy_id == "TG_AWS_EC2_001"
}

test_ec2_imdsv1_object_metadata_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_instance.legacy_obj",
		"type": "aws_instance",
		"change": {"after": {"metadata_options": {"http_tokens": "optional"}}},
	}]}
	count(result) == 1
}

test_ec2_missing_metadata_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_instance.bare",
		"type": "aws_instance",
		"change": {"after": {}},
	}]}
	count(result) == 1
}

test_ec2_imdsv2_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_instance.secure",
		"type": "aws_instance",
		"change": {"after": {"metadata_options": {"http_tokens": "required"}}},
	}]}
	not ec2_findings(result)
}

ec2_findings(result) if {
	some finding in result
	finding.policy_id == "TG_AWS_EC2_001"
}
