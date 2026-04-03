terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_eks_cluster" "platform" {
  name     = "terraguard-demo"
  role_arn = "arn:aws:iam::123456789012:role/demo"

  vpc_config {
    subnet_ids              = ["subnet-public-a", "subnet-public-b"]
    endpoint_public_access  = true
    endpoint_private_access = false
  }

  enabled_cluster_log_types = []
}

resource "aws_eks_node_group" "public_nodes" {
  cluster_name    = aws_eks_cluster.platform.name
  node_group_name = "public-nodes"
  node_role_arn   = "arn:aws:iam::123456789012:role/demo-node"
  subnet_ids      = ["subnet-public-a", "subnet-public-b"]
}

