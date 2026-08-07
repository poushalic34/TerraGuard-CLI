package terraguard

import rego.v1

test_eks_irsa_wildcard_action_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_iam_role.irsa_open",
		"type": "aws_iam_role",
		"change": {"after": {
			"assume_role_policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE\"},\"Action\":\"*\"}]}",
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_010"]) == 1
}

test_eks_irsa_scoped_action_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_iam_role.irsa_scoped",
		"type": "aws_iam_role",
		"change": {"after": {
			"assume_role_policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\"}]}",
		}},
	}]}
	not eks_iam_findings(result)
}

eks_iam_findings(result) if {
	some finding in result
	finding.policy_id == "TG_AWS_EKS_010"
}
