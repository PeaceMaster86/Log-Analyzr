variable "region" {
  type    = string
  default = "us-east-1"
}

variable "raw_log_bucket" {
  type    = string
  default = "siem-raw-logs-prod"
}

variable "opensearch_domain" {
  type    = string
  default = "siem-opensearch"
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "security_group_id" {
  type = string
}
