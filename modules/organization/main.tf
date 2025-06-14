# GCP Compliance Module - Organization Level
# Implements organization-wide compliance controls that work with limited permissions

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.29.0"
    }
  }
}

# Optional remote state for break-glass group
data "terraform_remote_state" "breakglass" {
  count   = var.break_glass_remote_state != null && var.break_glass_group == "" ? 1 : 0
  backend = var.break_glass_remote_state.backend
  config  = var.break_glass_remote_state.config
}

locals {
  # Use provided break-glass group or fall back to remote state
  effective_break_glass_group = (
    var.break_glass_group != "" ? var.break_glass_group :
    var.break_glass_remote_state != null ? try(data.terraform_remote_state.breakglass[0].outputs.break_glass_group, "") :
    ""
  )
  
  # Organization resource for deny policies
  org_resource = "cloudresourcemanager.googleapis.com%2Forganizations%2F${var.organization_id}"
  
  # Exception principals
  exception_principals = concat(
    [
      "principalSet://goog/group/${local.effective_break_glass_group}"
    ],
    # Add any super admins from remote state
    var.break_glass_remote_state != null ? [
      for admin in try(data.terraform_remote_state.breakglass[0].outputs.super_admins, []) :
      "principal://goog/subject/${admin}"
    ] : [],
    # Additional exceptions
    var.additional_exception_principals
  )
}

# Organization-wide baseline compliance controls
# NOTE: Very few permissions work at organization level
resource "google_iam_deny_policy" "org_baseline_security" {
  count = var.enable_baseline_controls ? 1 : 0
  
  parent       = local.org_resource
  name         = "org-compliance-baseline-security"
  display_name = "Organization Compliance - Baseline Security"
  
  rules {
    description = "Prevent dangerous security operations organization-wide"
    
    deny_rule {
      # Only permissions that actually work at org level
      denied_permissions = [
        "iam.googleapis.com/serviceAccountKeys.create",
        "iam.googleapis.com/serviceAccountKeys.delete"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = local.exception_principals
    }
  }
}

# Organization-wide audit protection
resource "google_organization_iam_audit_config" "org_audit_logs" {
  count = var.enable_audit_logging ? 1 : 0
  
  org_id = var.organization_id
  service = "allServices"
  
  # Enable all audit log types
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  
  audit_log_config {
    log_type = "DATA_READ"
  }
  
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# Monitor critical IAM changes at org level
resource "google_cloud_asset_organization_feed" "compliance_monitor" {
  count = var.enable_compliance_monitoring ? 1 : 0
  
  billing_project = var.monitoring_project_id
  org_id         = var.organization_id
  feed_id        = "compliance-iam-changes"
  
  content_type = "IAM_POLICY"
  
  asset_types = [
    "cloudresourcemanager.googleapis.com/Organization",
    "cloudresourcemanager.googleapis.com/Folder",
    "cloudresourcemanager.googleapis.com/Project",
    "iam.googleapis.com/ServiceAccount"
  ]
  
  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.compliance_events[0].id
    }
  }
}

# PubSub topic for compliance events
resource "google_pubsub_topic" "compliance_events" {
  count = var.enable_compliance_monitoring ? 1 : 0
  
  project = var.monitoring_project_id
  name    = "org-compliance-events"
  
  labels = {
    purpose = "compliance-monitoring"
    scope   = "organization"
  }
}

# Organization policy constraints for additional compliance
resource "google_org_policy_policy" "require_iam_conditions" {
  count = var.enable_org_policies ? 1 : 0
  
  name   = "${var.organization_id}/policies/iam.allowServiceAccountCredentialLifetimeExtension"
  parent = var.organization_id
  
  spec {
    rules {
      enforce = "FALSE"
    }
  }
}

resource "google_org_policy_policy" "disable_service_account_creation" {
  count = var.enable_org_policies && var.restrict_service_account_creation ? 1 : 0
  
  name   = "${var.organization_id}/policies/iam.disableServiceAccountCreation"
  parent = var.organization_id
  
  spec {
    rules {
      enforce = "TRUE"
      
      # Allow specific projects to create service accounts
      dynamic "condition" {
        for_each = var.service_account_creation_projects
        content {
          expression = "resource.name.matches('projects/${condition.value}/.*')"
          title      = "Allow SA creation in ${condition.value}"
        }
      }
    }
  }
}

# Restrict external IPs organization-wide
resource "google_org_policy_policy" "restrict_external_ips" {
  count = var.enable_org_policies && var.restrict_external_ips ? 1 : 0
  
  name   = "${var.organization_id}/policies/compute.vmExternalIpAccess"
  parent = var.organization_id
  
  spec {
    rules {
      # Deny all external IPs by default
      deny_all = "TRUE"
      
      # Allow for specific projects if needed
      dynamic "condition" {
        for_each = var.external_ip_allowed_projects
        content {
          expression = "resource.name.matches('projects/${condition.value}/.*')"
          title      = "Allow external IPs in ${condition.value}"
        }
      }
    }
  }
}

# Monitoring alert for compliance violations
resource "google_monitoring_alert_policy" "org_compliance_violations" {
  count = var.enable_compliance_monitoring ? 1 : 0
  
  project      = var.monitoring_project_id
  display_name = "Organization Compliance Violations"
  
  conditions {
    display_name = "IAM Deny Policy Violation"
    
    condition_matched_log {
      filter = <<-EOT
        protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
        AND protoPayload.status.code=7
        AND protoPayload.status.message=~"Denied by IAM deny policy"
        AND protoPayload.response.error.details.violations.errorMessage=~"org-compliance-"
      EOT
    }
  }
  
  notification_channels = var.alert_notification_channels
  
  alert_strategy {
    notification_rate_limit {
      period = "300s"  # 5 minutes
    }
  }
  
  documentation {
    content = "Organization-level compliance control violation detected. Review audit logs for details."
  }
}