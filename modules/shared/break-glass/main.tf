# Break-glass Integration Module
# Provides common break-glass patterns and validation

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.29.0"
    }
  }
}

# Optional remote state for break-glass configuration
data "terraform_remote_state" "breakglass" {
  count   = var.use_remote_state ? 1 : 0
  backend = var.remote_state_backend
  config  = var.remote_state_config
}

# Validate break-glass group exists
data "google_group" "break_glass" {
  count = var.validate_group ? 1 : 0
  email = local.effective_break_glass_group
}

locals {
  # Determine break-glass group from various sources
  effective_break_glass_group = coalesce(
    var.break_glass_group,
    var.use_remote_state ? try(data.terraform_remote_state.breakglass[0].outputs.break_glass_group, "") : "",
    ""
  )
  
  # Validate we have a break-glass group
  has_break_glass_group = local.effective_break_glass_group != ""
  
  # Build standard exception principals
  break_glass_principals = local.has_break_glass_group ? [
    "principalSet://goog/group/${local.effective_break_glass_group}"
  ] : []
  
  # Add super admins from remote state if available
  super_admin_principals = var.use_remote_state ? [
    for admin in try(data.terraform_remote_state.breakglass[0].outputs.super_admins, []) :
    "principal://goog/subject/${admin}"
  ] : []
  
  # Combine all exception principals
  all_exception_principals = distinct(concat(
    local.break_glass_principals,
    local.super_admin_principals,
    var.additional_exception_principals
  ))
  
  # Get PAM configuration from remote state
  pam_config = var.use_remote_state ? {
    entitlement_name = try(data.terraform_remote_state.breakglass[0].outputs.pam_entitlement_name, null)
    requester_group  = try(data.terraform_remote_state.breakglass[0].outputs.requester_group, null)
    approver_group   = try(data.terraform_remote_state.breakglass[0].outputs.approver_group, null)
  } : null
}

# Validation resource
resource "null_resource" "validate_break_glass" {
  count = var.require_break_glass ? 1 : 0
  
  triggers = {
    break_glass_group = local.effective_break_glass_group
  }
  
  provisioner "local-exec" {
    command = <<-EOT
      if [ -z "${local.effective_break_glass_group}" ]; then
        echo "ERROR: Break-glass group is required but not configured."
        echo "Set break_glass_group variable or configure remote state."
        exit 1
      fi
      
      # Optionally validate group exists in Google Workspace
      if [ "${var.validate_group}" = "true" ]; then
        if ! gcloud identity groups describe "${local.effective_break_glass_group}" >/dev/null 2>&1; then
          echo "WARNING: Break-glass group ${local.effective_break_glass_group} not found in Google Workspace"
        fi
      fi
    EOT
  }
  
  lifecycle {
    precondition {
      condition     = !var.require_break_glass || local.has_break_glass_group
      error_message = "Break-glass group must be configured when require_break_glass is true."
    }
  }
}

# Create a monitoring dashboard for break-glass usage
resource "google_monitoring_dashboard" "break_glass_usage" {
  count = var.create_monitoring_dashboard && var.monitoring_project_id != "" ? 1 : 0
  
  project        = var.monitoring_project_id
  dashboard_json = jsonencode({
    displayName = "Break-glass Access Monitoring"
    mosaicLayout = {
      columns = 12
      tiles = [
        {
          width  = 6
          height = 4
          widget = {
            title = "Break-glass Access Requests"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "resource.type=\"audited_resource\" AND protoPayload.serviceName=\"privilegedaccessmanager.googleapis.com\""
                  }
                }
              }]
            }
          }
        },
        {
          xPos   = 6
          width  = 6
          height = 4
          widget = {
            title = "Deny Policy Violations"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "protoPayload.status.code=7 AND protoPayload.status.message=~\"Denied by IAM deny policy\""
                  }
                }
              }]
            }
          }
        },
        {
          yPos   = 4
          width  = 12
          height = 4
          widget = {
            title = "Break-glass Group Actions"
            logsPanel = {
              filter = "protoPayload.authenticationInfo.principalEmail=~\".*@${local.effective_break_glass_group}\""
            }
          }
        }
      ]
    }
  })
}

# Alert for break-glass usage
resource "google_monitoring_alert_policy" "break_glass_usage_alert" {
  count = var.create_usage_alerts && var.monitoring_project_id != "" ? 1 : 0
  
  project      = var.monitoring_project_id
  display_name = "Break-glass Access Used"
  
  conditions {
    display_name = "Break-glass access requested or used"
    
    condition_matched_log {
      filter = <<-EOT
        (protoPayload.serviceName="privilegedaccessmanager.googleapis.com" 
         AND protoPayload.methodName=~".*CreateGrant.*")
        OR
        (protoPayload.authenticationInfo.principalEmail=~".*@${local.effective_break_glass_group}")
      EOT
    }
  }
  
  notification_channels = var.alert_notification_channels
  
  documentation {
    content = <<-EOT
      Break-glass access has been requested or used.
      
      Group: ${local.effective_break_glass_group}
      PAM Entitlement: ${local.pam_config != null ? local.pam_config.entitlement_name : "N/A"}
      
      Review the logs immediately to ensure this is authorized.
    EOT
  }
  
  alert_strategy {
    auto_close = "86400s"  # 24 hours
  }
}