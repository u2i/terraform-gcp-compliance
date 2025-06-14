# ISO 27001 Compliance Controls (Project Level)
# Implements a subset of controls that work at project level

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

variable "enabled" {
  type    = bool
  default = true
}

# A.9 - Access Control (Simplified)
resource "google_iam_deny_policy" "iso27001_access_control" {
  count = var.enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "iso27001-a9-access-control"
  display_name = "ISO 27001 A.9 - Access Control"
  
  rules {
    description = "Restrict service account impersonation"
    
    deny_rule {
      denied_permissions = [
        "iam.googleapis.com/serviceAccounts.getAccessToken",
        "iam.googleapis.com/serviceAccounts.signBlob",
        "iam.googleapis.com/serviceAccounts.signJwt"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# A.10 - Cryptography (Simplified)
resource "google_iam_deny_policy" "iso27001_cryptography" {
  count = var.enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "iso27001-a10-cryptography"
  display_name = "ISO 27001 A.10 - Cryptographic Controls"
  
  rules {
    description = "Protect cryptographic operations"
    
    deny_rule {
      denied_permissions = [
        "cloudkms.googleapis.com/cryptoKeyVersions.destroy",
        "cloudkms.googleapis.com/cryptoKeys.update"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# A.12 - Operations Security (Simplified)
resource "google_iam_deny_policy" "iso27001_operations" {
  count = var.enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "iso27001-a12-operations"
  display_name = "ISO 27001 A.12 - Operations Security"
  
  rules {
    description = "Protect critical operations"
    
    deny_rule {
      denied_permissions = [
        "storage.googleapis.com/objects.delete",
        "bigquery.googleapis.com/tables.delete",
        "bigquery.googleapis.com/datasets.delete"
      ]
      
      # Only during business hours
      denial_condition {
        title       = "Business hours only"
        description = "Destructive operations only during business hours"
        expression  = <<-EOT
          request.time.getHours("America/New_York") < 6 ||
          request.time.getHours("America/New_York") > 20
        EOT
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# Monitoring for ISO 27001 violations
resource "google_monitoring_alert_policy" "iso27001_violations" {
  count = var.enabled ? 1 : 0
  
  project      = var.project_id
  display_name = "ISO 27001 Deny Policy Violations"
  combiner     = "OR"
  
  conditions {
    display_name = "Deny policy violation detected"
    
    condition_matched_log {
      filter = <<-EOT
        protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
        AND protoPayload.status.code=7
        AND protoPayload.status.message=~"Denied by IAM deny policy"
        AND protoPayload.response.error.details.violations.errorMessage=~"iso27001-"
      EOT
    }
  }
  
  documentation {
    content = "ISO 27001 compliance control violation detected. Review the audit logs for details."
  }
}

output "iso27001_controls" {
  value = {
    access_control = {
      enabled = var.enabled
      policy_id = var.enabled ? google_iam_deny_policy.iso27001_access_control[0].id : null
    }
    cryptography = {
      enabled = var.enabled
      policy_id = var.enabled ? google_iam_deny_policy.iso27001_cryptography[0].id : null
    }
    operations = {
      enabled = var.enabled
      policy_id = var.enabled ? google_iam_deny_policy.iso27001_operations[0].id : null
    }
    monitoring = {
      enabled = var.enabled
      alert_policy_id = var.enabled ? google_monitoring_alert_policy.iso27001_violations[0].id : null
    }
  }
}
