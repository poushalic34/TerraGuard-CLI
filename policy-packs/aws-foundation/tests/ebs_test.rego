package terraguard

import rego.v1

test_ebs_unencrypted_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_ebs_volume.unencrypted",
		"type": "aws_ebs_volume",
		"change": {"after": {"encrypted": false}},
	}]}
	count(result) == 1
	some finding in result
	finding.policy_id == "TG_AWS_EBS_001"
}

test_ebs_encrypted_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_ebs_volume.secure",
		"type": "aws_ebs_volume",
		"change": {"after": {"encrypted": true}},
	}]}
	not ebs_findings(result)
}

ebs_findings(result) if {
	some finding in result
	finding.policy_id == "TG_AWS_EBS_001"
}
