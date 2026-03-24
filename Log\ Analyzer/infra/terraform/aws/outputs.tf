output "raw_log_bucket" {
  value = aws_s3_bucket.raw_logs.id
}

output "opensearch_endpoint" {
  value = aws_opensearch_domain.siem.endpoint
}

output "msk_bootstrap_brokers" {
  value = aws_msk_cluster.siem_stream.bootstrap_brokers
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.siem.name
}
