# Outputs for Folder-level Compliance Module

output "folder_id" {
  description = "The folder ID where controls are applied"
  value       = var.folder_id
}

output "folder_type" {
  description = "The type of folder (production, staging, development)"
  value       = var.folder_type
}

output "compliance_level" {
  description = "The determined compliance level for this folder"
  value       = local.compliance_level
}

output "effective_break_glass_group" {
  description = "The break-glass group being used"
  value       = local.effective_break_glass_group
}

output "deny_policy_ids" {
  description = "IDs of created deny policies"
  value = {
    iam_protection      = try(google_iam_deny_policy.folder_iam_protection[0].name, null)
    resource_protection = try(google_iam_deny_policy.folder_resource_protection[0].name, null)
    service_restrictions = try(google_iam_deny_policy.folder_service_restrictions[0].name, null)
  }
}

output "org_policies" {
  description = "Organization policies applied to the folder"
  value = {
    location_restrictions = var.enable_location_restrictions && length(var.allowed_locations) > 0
    trusted_images       = var.enable_trusted_image_projects && length(var.trusted_image_projects) > 0
    ingress_restrictions = var.folder_type == "production"
  }
}

output "audit_logging_enabled" {
  description = "Whether audit logging is enabled for the folder"
  value       = var.enable_audit_logging
}

output "monitoring_enabled" {
  description = "Whether compliance monitoring is enabled"
  value       = var.enable_compliance_monitoring
}