# Outputs for Organization-level Compliance Module

output "organization_id" {
  description = "The organization ID where controls are applied"
  value       = var.organization_id
}

output "effective_break_glass_group" {
  description = "The break-glass group being used"
  value       = local.effective_break_glass_group
}

output "deny_policy_ids" {
  description = "IDs of created deny policies"
  value = {
    baseline_security = try(google_iam_deny_policy.org_baseline_security[0].name, null)
  }
}

output "compliance_monitoring" {
  description = "Compliance monitoring configuration"
  value = var.enable_compliance_monitoring ? {
    asset_feed_name = google_cloud_asset_organization_feed.compliance_monitor[0].name
    pubsub_topic    = google_pubsub_topic.compliance_events[0].id
    alert_policy    = google_monitoring_alert_policy.org_compliance_violations[0].name
  } : null
}

output "org_policies_enabled" {
  description = "Organization policies that are enabled"
  value = {
    iam_conditions_required           = var.enable_org_policies
    service_account_creation_restricted = var.enable_org_policies && var.restrict_service_account_creation
    external_ips_restricted           = var.enable_org_policies && var.restrict_external_ips
  }
}

output "audit_logging_enabled" {
  description = "Whether organization-wide audit logging is enabled"
  value       = var.enable_audit_logging
}