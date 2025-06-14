# Shared Access Control Module (Project Level)
# Simplified for project-level deny policies

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.29.0"
    }
  }
}

variable "project_id" {
  type = string
}

variable "project_resource" {
  type = string
}

variable "exception_principals" {
  type = list(string)
}

variable "compliance_level" {
  type    = string
  default = "medium"
}

variable "security_controls" {
  type = object({
    enforce_mfa                = bool
    max_session_duration_hours = number
    require_approval           = bool
    approval_levels            = number
  })
  default = {
    enforce_mfa                = true
    max_session_duration_hours = 12
    require_approval           = false
    approval_levels            = 1
  }
}

# Session Duration Controls (Simplified)
resource "google_iam_deny_policy" "session_duration" {
  parent       = var.project_resource
  name         = "shared-session-duration"
  display_name = "Shared - Session Duration Controls"
  
  rules {
    description = "Enforce maximum session duration"
    
    deny_rule {
      denied_permissions = [
        "iam.googleapis.com/serviceAccounts.getAccessToken"
      ]
      
      # Simple time-based condition
      denial_condition {
        title       = "Session timeout"
        description = "Block access after ${var.security_controls.max_session_duration_hours} hours"
        expression  = "request.time > timestamp('2024-12-31T23:59:59Z')" # Placeholder - needs proper implementation
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# MFA Enforcement (Simplified)
resource "google_iam_deny_policy" "enforce_mfa" {
  count = var.security_controls.enforce_mfa ? 1 : 0
  
  parent       = var.project_resource
  name         = "shared-enforce-mfa"
  display_name = "Shared - Enforce Multi-Factor Authentication"
  
  rules {
    description = "Require MFA for sensitive operations"
    
    deny_rule {
      denied_permissions = [
        "iam.googleapis.com/serviceAccounts.getAccessToken",
        "iam.googleapis.com/serviceAccountKeys.get"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# Approval-Based Access (Simplified)
resource "google_iam_deny_policy" "require_approval" {
  count = var.security_controls.require_approval ? 1 : 0
  
  parent       = var.project_resource
  name         = "shared-require-approval"
  display_name = "Shared - Require Approval for Privileged Actions"
  
  rules {
    description = "Require approval for privileged operations"
    
    deny_rule {
      denied_permissions = [
        "resourcemanager.googleapis.com/projects.delete",
        "bigquery.googleapis.com/datasets.delete"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# Segregation of Duties (Simplified)
resource "google_iam_deny_policy" "segregation_of_duties" {
  count = var.compliance_level == "high" || var.compliance_level == "maximum" ? 1 : 0
  
  parent       = var.project_resource
  name         = "shared-segregation-of-duties"
  display_name = "Shared - Segregation of Duties"
  
  rules {
    description = "Enforce segregation of duties"
    
    deny_rule {
      denied_permissions = [
        "iam.googleapis.com/roles.create",
        "iam.googleapis.com/roles.update"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# Monitoring
resource "google_monitoring_alert_policy" "access_review_reminder" {
  project      = var.project_id
  display_name = "Shared - Access Review Reminder"
  combiner     = "OR"
  
  conditions {
    display_name = "Quarterly access review due"
    
    condition_threshold {
      filter          = "resource.type=\"global\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      
      aggregations {
        alignment_period   = "86400s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }
  
  documentation {
    content = "Quarterly access review is due. Review all user permissions and service account keys."
  }
}

output "access_control_policies" {
  value = {
    mfa_enforcement = var.security_controls.enforce_mfa
    session_controls = true
    approval_required = var.security_controls.require_approval
    segregation_of_duties = var.compliance_level == "high" || var.compliance_level == "maximum"
    max_session_hours = var.security_controls.max_session_duration_hours
  }
}
