package terraguard

import rego.v1

test_eks_public_endpoint_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_cluster.platform",
		"type": "aws_eks_cluster",
		"change": {"after": {
			"vpc_config": [{"endpoint_public_access": true, "endpoint_private_access": true}],
			"enabled_cluster_log_types": ["api", "audit", "authenticator"],
			"encryption_config": [{"resources": ["secrets"]}],
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_001"]) == 1
}

test_eks_logging_null_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_cluster.platform",
		"type": "aws_eks_cluster",
		"change": {"after": {
			"vpc_config": [{"endpoint_public_access": false}],
			"enabled_cluster_log_types": null,
			"encryption_config": [{"resources": ["secrets"]}],
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_002"]) == 1
}

test_eks_logging_disabled_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_cluster.platform",
		"type": "aws_eks_cluster",
		"change": {"after": {
			"vpc_config": [{"endpoint_public_access": false}],
			"enabled_cluster_log_types": [],
			"encryption_config": [{"resources": ["secrets"]}],
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_002"]) == 1
}

test_eks_secrets_unencrypted_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_cluster.platform",
		"type": "aws_eks_cluster",
		"change": {"after": {
			"vpc_config": [{"endpoint_public_access": false}],
			"enabled_cluster_log_types": ["api", "audit", "authenticator"],
			"encryption_config": [],
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_003"]) == 1
}

test_eks_open_public_cidrs_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_cluster.platform",
		"type": "aws_eks_cluster",
		"change": {"after": {
			"vpc_config": [{
				"endpoint_public_access": true,
				"endpoint_private_access": true,
				"public_access_cidrs": ["0.0.0.0/0"],
			}],
			"enabled_cluster_log_types": ["api", "audit", "authenticator"],
			"encryption_config": [{"resources": ["secrets"]}],
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_005"]) == 1
}

test_eks_missing_audit_log_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_cluster.platform",
		"type": "aws_eks_cluster",
		"change": {"after": {
			"vpc_config": [{"endpoint_public_access": false}],
			"enabled_cluster_log_types": ["api", "authenticator"],
			"encryption_config": [{"resources": ["secrets"]}],
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_006"]) == 1
}

test_eks_missing_authenticator_log_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_cluster.platform",
		"type": "aws_eks_cluster",
		"change": {"after": {
			"vpc_config": [{"endpoint_public_access": false}],
			"enabled_cluster_log_types": ["api", "audit"],
			"encryption_config": [{"resources": ["secrets"]}],
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_007"]) == 1
}

test_eks_public_without_private_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_cluster.platform",
		"type": "aws_eks_cluster",
		"change": {"after": {
			"vpc_config": [{
				"endpoint_public_access": true,
				"endpoint_private_access": false,
				"public_access_cidrs": ["10.0.0.0/8"],
			}],
			"enabled_cluster_log_types": ["api", "audit", "authenticator"],
			"encryption_config": [{"resources": ["secrets"]}],
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_011"]) == 1
}

test_eks_secure_cluster_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_cluster.platform",
		"type": "aws_eks_cluster",
		"change": {"after": {
			"vpc_config": [{"endpoint_public_access": false, "endpoint_private_access": true}],
			"enabled_cluster_log_types": ["api", "audit", "authenticator"],
			"encryption_config": [{"resources": ["secrets"], "provider": [{"key_arn": "arn:aws:kms:us-east-1:123456789012:key/demo"}]}],
		}},
	}]}
	not cluster_findings(result)
}

cluster_findings(result) if {
	some finding in result
	finding.policy_id in {
		"TG_AWS_EKS_001",
		"TG_AWS_EKS_002",
		"TG_AWS_EKS_003",
		"TG_AWS_EKS_005",
		"TG_AWS_EKS_006",
		"TG_AWS_EKS_007",
		"TG_AWS_EKS_011",
	}
}
