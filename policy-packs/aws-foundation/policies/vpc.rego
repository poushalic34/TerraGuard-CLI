package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_vpc"
	not has_flow_log_for_vpc(resource.address)

	finding := {
		"policy_id": "TG_AWS_VPC_001",
		"title": "VPC flow logs should be configured",
		"severity": "medium",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "No aws_flow_log resource was found in this Terraform plan.",
		"remediation": "Create an aws_flow_log resource for the VPC and send logs to CloudWatch Logs or S3.",
	}
}

has_flow_log_for_vpc(address) if {
	flow_log := input.resource_changes[_]
	flow_log.type == "aws_flow_log"
	contains(sprintf("%v", [flow_log.change.after.resource_id]), address)
}

