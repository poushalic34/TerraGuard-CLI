package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	after := resource.change.after
	ingress := after.ingress[_]
	ingress.cidr_blocks[_] == "0.0.0.0/0"
	port_allowed(ingress, 22)

	finding := {
		"policy_id": "TG_AWS_SG_001",
		"title": "Security groups must not expose SSH to the internet",
		"severity": "critical",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "Security group allows SSH ingress from 0.0.0.0/0.",
		"remediation": "Restrict SSH ingress to approved CIDR ranges or use SSM Session Manager.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	after := resource.change.after
	ingress := after.ingress[_]
	ingress.cidr_blocks[_] == "0.0.0.0/0"
	port_allowed(ingress, 3389)

	finding := {
		"policy_id": "TG_AWS_SG_002",
		"title": "Security groups must not expose RDP to the internet",
		"severity": "critical",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "Security group allows RDP ingress from 0.0.0.0/0.",
		"remediation": "Restrict RDP ingress to approved CIDR ranges or disable RDP exposure.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	after := resource.change.after
	ingress := after.ingress[_]
	ingress.cidr_blocks[_] == "0.0.0.0/0"
	open_all_ports(ingress)

	finding := {
		"policy_id": "TG_AWS_SG_003",
		"title": "Security groups must not expose all ports to the internet",
		"severity": "critical",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "Security group allows all ports from 0.0.0.0/0.",
		"remediation": "Replace wide-open ingress with least-privilege port ranges.",
	}
}

port_allowed(ingress, port) if {
	ingress.from_port <= port
	ingress.to_port >= port
}

open_all_ports(ingress) if {
	ingress.from_port == 0
	ingress.to_port == 0
}

open_all_ports(ingress) if {
	ingress.from_port == 0
	ingress.to_port == 65535
}

open_all_ports(ingress) if {
	ingress.protocol == "-1"
}
