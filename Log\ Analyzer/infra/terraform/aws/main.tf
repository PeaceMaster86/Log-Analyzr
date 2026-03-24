terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_s3_bucket" "raw_logs" {
  bucket = var.raw_log_bucket
}

resource "aws_opensearch_domain" "siem" {
  domain_name    = var.opensearch_domain
  engine_version = "OpenSearch_2.13"

  cluster_config {
    instance_type = "t3.small.search"
    instance_count = 2
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 20
  }
}

resource "aws_msk_cluster" "siem_stream" {
  cluster_name           = "siem-stream"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = "kafka.t3.small"
    client_subnets  = var.private_subnet_ids
    security_groups = [var.security_group_id]

    storage_info {
      ebs_storage_info {
        volume_size = 200
      }
    }
  }
}

resource "aws_ecs_cluster" "siem" {
  name = "siem-detection"
}

# Deploy each Python microservice as an ECS service behind this cluster.
