package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_eks_node_group"
	after := resource.change.after
	contains(sprintf("%v", [after.subnet_ids]), "public")

	finding := {
		"policy_id": "TG_AWS_EKS_004",
		"title": "EKS node groups should not use public subnets",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "EKS node group subnet identifiers appear to reference public subnets.",
		"remediation": "Place worker nodes in private subnets and route outbound traffic through NAT.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_eks_node_group"
	after := resource.change.after
	remote := object.get(after, "remote_access", [])
	is_array(remote)
	count(remote) > 0
	object.get(remote[0], "ec2_ssh_key", null) != null

	finding := {
		"policy_id": "TG_AWS_EKS_008",
		"title": "EKS node groups should not enable SSH remote access",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "EKS node group configures SSH remote access.",
		"remediation": "Remove remote_access and manage nodes with SSM Session Manager.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_eks_node_group"
	after := resource.change.after
	remote := object.get(after, "remote_access", {})
	is_object(remote)
	object.get(remote, "ec2_ssh_key", null) != null

	finding := {
		"policy_id": "TG_AWS_EKS_008",
		"title": "EKS node groups should not enable SSH remote access",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "EKS node group configures SSH remote access.",
		"remediation": "Remove remote_access and manage nodes with SSM Session Manager.",
	}
}
