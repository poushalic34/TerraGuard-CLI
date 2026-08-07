terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}

resource "aws_eks_cluster" "platform" {
  name     = "terraguard-secure"
  role_arn = "arn:aws:iam::123456789012:role/demo"

  vpc_config {
    subnet_ids              = ["subnet-private-a", "subnet-private-b"]
    endpoint_public_access  = false
    endpoint_private_access = true
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator"]

  encryption_config {
    provider {
      key_arn = "arn:aws:kms:us-east-1:123456789012:key/demo"
    }
    resources = ["secrets"]
  }
}

resource "aws_eks_node_group" "private_nodes" {
  cluster_name    = aws_eks_cluster.platform.name
  node_group_name = "private-nodes"
  node_role_arn   = "arn:aws:iam::123456789012:role/demo-node"
  subnet_ids      = ["subnet-private-a", "subnet-private-b"]

  scaling_config {
    desired_size = 1
    max_size     = 1
    min_size     = 1
  }
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name  = aws_eks_cluster.platform.name
  addon_name    = "vpc-cni"
  addon_version = "v1.18.0-eksbuild.1"
}

variable "environment" {
  type    = string
  default = "demo"
}
