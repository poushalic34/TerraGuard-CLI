package terraguard

import rego.v1

test_eks_public_node_group_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_node_group.public",
		"type": "aws_eks_node_group",
		"change": {"after": {"subnet_ids": ["subnet-public-a", "subnet-public-b"]}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_004"]) == 1
}

test_eks_node_group_ssh_remote_access_array_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_node_group.ssh",
		"type": "aws_eks_node_group",
		"change": {"after": {
			"subnet_ids": ["subnet-private-a"],
			"remote_access": [{"ec2_ssh_key": "bastion-key"}],
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_008"]) == 1
}

test_eks_node_group_ssh_remote_access_object_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_node_group.ssh_obj",
		"type": "aws_eks_node_group",
		"change": {"after": {
			"subnet_ids": ["subnet-private-a"],
			"remote_access": {"ec2_ssh_key": "bastion-key"},
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_008"]) == 1
}

test_eks_private_node_group_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_node_group.private",
		"type": "aws_eks_node_group",
		"change": {"after": {"subnet_ids": ["subnet-private-a", "subnet-private-b"]}},
	}]}
	not node_findings(result)
}

node_findings(result) if {
	some finding in result
	finding.policy_id in {"TG_AWS_EKS_004", "TG_AWS_EKS_008"}
}
