# Outputs for Break-glass Integration Module

output "break_glass_group" {
  description = "The effective break-glass group email"
  value       = local.effective_break_glass_group
}

output "break_glass_principal" {
  description = "The break-glass group principal for use in deny policies"
  value       = local.has_break_glass_group ? "principalSet://goog/group/${local.effective_break_glass_group}" : null
}

output "exception_principals" {
  description = "Complete list of exception principals for deny policies"
  value       = local.all_exception_principals
}

output "has_break_glass_configured" {
  description = "Whether break-glass is properly configured"
  value       = local.has_break_glass_group
}

output "pam_configuration" {
  description = "PAM configuration from remote state (if available)"
  value       = local.pam_config
  sensitive   = true
}

output "monitoring_dashboard_url" {
  description = "URL to the break-glass monitoring dashboard"
  value = var.create_monitoring_dashboard && var.monitoring_project_id != "" ? (
    "https://console.cloud.google.com/monitoring/dashboards/custom/${try(google_monitoring_dashboard.break_glass_usage[0].id, "")}"
  ) : null
}

output "alert_policy_name" {
  description = "Name of the break-glass usage alert policy"
  value       = try(google_monitoring_alert_policy.break_glass_usage_alert[0].name, null)
}

output "validation_status" {
  description = "Status of break-glass validation"
  value = {
    group_configured = local.has_break_glass_group
    group_validated  = var.validate_group && length(data.google_group.break_glass) > 0
    using_remote_state = var.use_remote_state && length(data.terraform_remote_state.breakglass) > 0
  }
}