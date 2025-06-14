# SOC 2 Type II Compliance Controls (Project Level)
# Implements Trust Services Criteria at project level

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

variable "trust_criteria" {
  type    = list(string)
  default = ["security"]
}

locals {
  security_enabled = contains(var.trust_criteria, "security")
  availability_enabled = contains(var.trust_criteria, "availability")
  confidentiality_enabled = contains(var.trust_criteria, "confidentiality")
}

# CC6.1 - Logical Access Controls
resource "google_iam_deny_policy" "soc2_access_control" {
  count = local.security_enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "soc2-cc6-1-access-control"
  display_name = "SOC 2 CC6.1 - Logical Access Controls"
  
  rules {
    description = "Enforce logical access controls per TSC CC6.1"
    
    deny_rule {
      denied_permissions = [
        "iam.googleapis.com/serviceAccounts.getAccessToken",
        "iam.googleapis.com/serviceAccounts.signBlob",
        "iam.googleapis.com/serviceAccounts.signJwt",
        "iam.googleapis.com/serviceAccountKeys.get"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# CC7.2 - System Monitoring (Simplified)
resource "google_iam_deny_policy" "soc2_monitoring" {
  count = local.security_enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "soc2-cc7-2-monitoring"
  display_name = "SOC 2 CC7.2 - System Monitoring"
  
  rules {
    description = "Protect monitoring infrastructure"
    
    deny_rule {
      denied_permissions = [
        "logging.googleapis.com/exclusions.create",
        "logging.googleapis.com/exclusions.update"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# A1.2 - Availability Controls (Simplified)
resource "google_iam_deny_policy" "soc2_availability" {
  count = local.availability_enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "soc2-a1-2-availability"
  display_name = "SOC 2 A1.2 - Availability Controls"
  
  rules {
    description = "Protect system availability"
    
    deny_rule {
      denied_permissions = [
        "compute.googleapis.com/instances.delete",
        "compute.googleapis.com/instances.stop"
      ]
      
      # Only during maintenance windows
      denial_condition {
        title       = "Outside maintenance window"
        description = "Changes only allowed during maintenance"
        expression  = <<-EOT
          !(request.time.getHours("UTC") >= 2 && request.time.getHours("UTC") <= 4 && 
            request.time.getDayOfWeek("UTC") == 0)
        EOT
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# C1.2 - Confidentiality Controls (Simplified)
resource "google_iam_deny_policy" "soc2_confidentiality" {
  count = local.confidentiality_enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "soc2-c1-2-confidentiality"
  display_name = "SOC 2 C1.2 - Confidentiality Controls"
  
  rules {
    description = "Protect confidential information"
    
    deny_rule {
      denied_permissions = [
        "storage.googleapis.com/objects.get",
        "bigquery.googleapis.com/tables.getData"
      ]
      
      # Block external IPs (simplified)
      denial_condition {
        title       = "External access blocked"
        description = "Prevent access from outside organization"
        expression  = "!origin.ip.startsWith('10.') && !origin.ip.startsWith('172.16.') && !origin.ip.startsWith('192.168.')"
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# Monitoring for SOC 2 violations
resource "google_monitoring_alert_policy" "soc2_violations" {
  count = local.security_enabled ? 1 : 0
  
  project      = var.project_id
  display_name = "SOC 2 Deny Policy Violations"
  combiner     = "OR"
  
  conditions {
    display_name = "Deny policy violation detected"
    
    condition_matched_log {
      filter = <<-EOT
        protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
        AND protoPayload.status.code=7
        AND protoPayload.status.message=~"Denied by IAM deny policy"
        AND protoPayload.response.error.details.violations.errorMessage=~"soc2-"
      EOT
    }
  }
  
  documentation {
    content = "SOC 2 compliance control violation detected. Review the audit logs for details."
  }
}

output "soc2_controls" {
  value = {
    enabled_criteria = var.trust_criteria
    policies_created = {
      access_control = local.security_enabled
      monitoring = local.security_enabled
      availability = local.availability_enabled
      confidentiality = local.confidentiality_enabled
    }
  }
}
