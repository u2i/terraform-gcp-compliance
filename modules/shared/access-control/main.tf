# Shared Access Control Module
# Implements common access control patterns across all compliance frameworks

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
  validation {
    condition     = contains(["baseline", "medium", "high", "maximum"], var.compliance_level)
    error_message = "Compliance level must be one of: baseline, medium, high, maximum"
  }
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

locals {
  # Adjust controls based on compliance level
  mfa_required = var.security_controls.enforce_mfa || var.compliance_level != "baseline"
  approval_required = var.security_controls.require_approval || contains(["high", "maximum"], var.compliance_level)
  
  # Session duration limits by compliance level
  max_session_hours = min(
    var.security_controls.max_session_duration_hours,
    var.compliance_level == "maximum" ? 4 :
    var.compliance_level == "high" ? 8 :
    var.compliance_level == "medium" ? 12 :
    24
  )
}

# Multi-Factor Authentication Enforcement
resource "google_iam_deny_policy" "enforce_mfa" {
  count = local.mfa_required ? 1 : 0
  
  parent       = var.project_resource
  name         = "shared-enforce-mfa"
  display_name = "Shared - Enforce Multi-Factor Authentication"
  
  rules {
    description = "Require MFA for sensitive operations"
    
    deny_rule {
      denied_permissions = [
        # IAM changes
        "resourcemanager.projects.setIamPolicy",
        "iam.serviceAccounts.setIamPolicy",
        "iam.roles.create",
        "iam.roles.update",
        "iam.roles.delete",
        
        # Key management
        "iam.serviceAccountKeys.create",
        "cloudkms.cryptoKeys.create",
        "cloudkms.cryptoKeyVersions.destroy",
        
        # Data access (for high compliance levels)
        "${var.compliance_level == "maximum" ? "storage.objects.get" : ""}",
        "${var.compliance_level == "maximum" ? "bigquery.tables.getData" : ""}"
      ]
      
      denial_condition {
        title       = "MFA Required"
        description = "Multi-factor authentication is required for this operation"
        expression  = "!request.auth.access_levels.exists(l, l == 'mfa_verified')"
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# Session Duration Controls
resource "google_iam_deny_policy" "session_duration" {
  parent       = var.project_resource
  name         = "shared-session-duration"
  display_name = "Shared - Session Duration Controls"
  
  rules {
    description = "Enforce maximum session duration"
    
    deny_rule {
      denied_permissions = [
        # All permissions after session timeout
        "*"
      ]
      
      denial_condition {
        title       = "Session Expired"
        description = "Session has exceeded maximum duration of ${local.max_session_hours} hours"
        expression  = <<-EOT
          request.auth.claims.iat + duration('${local.max_session_hours}h') < request.time
        EOT
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# Approval-Based Access
resource "google_iam_deny_policy" "require_approval" {
  count = local.approval_required ? 1 : 0
  
  parent       = var.project_resource
  name         = "shared-require-approval"
  display_name = "Shared - Require Approval for Privileged Actions"
  
  rules {
    description = "Require approval for privileged operations"
    
    deny_rule {
      denied_permissions = [
        # Highly privileged operations
        "resourcemanager.projects.delete",
        "resourcemanager.projects.undelete",
        "iam.serviceAccounts.actAs",
        "compute.instances.setServiceAccount",
        "cloudkms.cryptoKeyVersions.useToDecrypt",
        
        # Mass data operations
        "bigquery.tables.delete",
        "storage.buckets.delete",
        "spanner.databases.drop"
      ]
      
      denial_condition {
        title       = "Approval Required"
        description = "This operation requires ${var.security_controls.approval_levels} approval(s)"
        expression  = <<-EOT
          !request.auth.claims.exists(c, c == 'approved_by') ||
          size(request.auth.claims.approved_by) < ${var.security_controls.approval_levels}
        EOT
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# Segregation of Duties
resource "google_iam_deny_policy" "segregation_of_duties" {
  count = contains(["high", "maximum"], var.compliance_level) ? 1 : 0
  
  parent       = var.project_resource
  name         = "shared-segregation-of-duties"
  display_name = "Shared - Segregation of Duties"
  
  rules {
    description = "Enforce segregation of duties for critical operations"
    
    deny_rule {
      denied_permissions = [
        # Prevent self-escalation
        "resourcemanager.projects.setIamPolicy",
        "iam.roles.update"
      ]
      
      denial_condition {
        title       = "Self-modification blocked"
        description = "Users cannot modify their own permissions"
        expression  = <<-EOT
          request.auth.principal in resource.policy.bindings.members
        EOT
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
  
  rules {
    description = "Separate deployment from approval roles"
    
    deny_rule {
      denied_permissions = [
        # Deployment permissions
        "run.services.create",
        "cloudfunctions.functions.create",
        "appengine.versions.create"
      ]
      
      denial_condition {
        title       = "Approvers cannot deploy"
        description = "Users with approval rights cannot perform deployments"
        expression  = "'approver' in request.auth.claims.roles"
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# Time-based Access Controls
resource "google_iam_deny_policy" "time_based_access" {
  count = var.compliance_level == "maximum" ? 1 : 0
  
  parent       = var.project_resource
  name         = "shared-time-based-access"
  display_name = "Shared - Time-based Access Controls"
  
  rules {
    description = "Restrict access outside business hours"
    
    deny_rule {
      denied_permissions = [
        # Administrative actions
        "resourcemanager.projects.setIamPolicy",
        "compute.instances.delete",
        "storage.buckets.delete"
      ]
      
      denial_condition {
        title       = "Business hours only"
        description = "Administrative actions only allowed during business hours"
        expression  = <<-EOT
          request.time.getHours("America/New_York") < 7 ||
          request.time.getHours("America/New_York") > 19 ||
          request.time.getDayOfWeek() == 0 ||
          request.time.getDayOfWeek() == 6
        EOT
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# Access Reviews and Recertification
resource "google_monitoring_alert_policy" "access_review_reminder" {
  project      = var.project_id
  display_name = "Shared - Access Review Reminder"
  
  conditions {
    display_name = "Quarterly access review due"
    
    condition_threshold {
      filter          = "resource.type=\"global\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      
      aggregations {
        alignment_period   = "86400s"  # Daily
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }
  
  documentation {
    content = "Quarterly access review is due. Review all user permissions and service account keys."
  }
  
  alert_strategy {
    notification_rate_limit {
      period = "7776000s"  # 90 days
    }
  }
}

output "access_control_policies" {
  value = {
    mfa_enforcement      = local.mfa_required
    session_controls     = true
    approval_required    = local.approval_required
    segregation_of_duties = contains(["high", "maximum"], var.compliance_level)
    time_based_access    = var.compliance_level == "maximum"
    max_session_hours    = local.max_session_hours
  }
}