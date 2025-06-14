# Monitoring Module - Placeholder
# TODO: Implement compliance monitoring

variable "project_id" { type = string }
variable "enabled_frameworks" { type = any }
variable "monitoring_config" { type = any }

output "dashboard_url" {
  value = "https://console.cloud.google.com/monitoring"
}