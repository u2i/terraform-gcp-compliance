# SOC 2 Type II Compliance Controls
# Implements Trust Services Criteria (TSC)

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
  # Options: security, availability, processing_integrity, confidentiality, privacy
}

locals {
  # Determine which criteria are enabled
  security_enabled              = contains(var.trust_criteria, "security")
  availability_enabled          = contains(var.trust_criteria, "availability")
  processing_integrity_enabled  = contains(var.trust_criteria, "processing_integrity")
  confidentiality_enabled      = contains(var.trust_criteria, "confidentiality")
  privacy_enabled              = contains(var.trust_criteria, "privacy")
}

# CC6.1 - Logical and Physical Access Controls
resource "google_iam_deny_policy" "soc2_access_control" {
  count = local.security_enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "soc2-cc6-1-access-control"
  display_name = "SOC 2 CC6.1 - Logical Access Controls"
  
  rules {
    description = "Enforce logical access controls per TSC CC6.1"
    
    deny_rule {
      denied_permissions = [
        # Prevent unauthorized access modifications
        "resourcemanager.projects.setIamPolicy",
        "iam.serviceAccounts.setIamPolicy",
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.signJwt",
        
        # Prevent key management changes
        "iam.serviceAccountKeys.create",
        "iam.serviceAccountKeys.delete"
      ]
      
      # Require MFA for these operations
      denial_condition {
        title       = "Require MFA"
        description = "Multi-factor authentication required"
        expression  = "!request.auth.access_levels.exists(l, l == 'mfa_verified')"
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# CC7.2 - System Monitoring
resource "google_iam_deny_policy" "soc2_monitoring" {
  count = local.security_enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "soc2-cc7-2-monitoring"
  display_name = "SOC 2 CC7.2 - System Monitoring"
  
  rules {
    description = "Protect monitoring infrastructure per TSC CC7.2"
    
    deny_rule {
      denied_permissions = [
        # Protect monitoring configuration
        "monitoring.alertPolicies.delete",
        "monitoring.alertPolicies.update",
        "monitoring.notificationChannels.delete",
        "monitoring.uptimeCheckConfigs.delete",
        "monitoring.dashboards.delete",
        
        # Protect logging configuration
        "logging.sinks.delete",
        "logging.sinks.update",
        "logging.exclusions.create",
        "logging.logMetrics.delete"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# A1.2 - Availability Controls
resource "google_iam_deny_policy" "soc2_availability" {
  count = local.availability_enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "soc2-a1-2-availability"
  display_name = "SOC 2 A1.2 - Availability Controls"
  
  rules {
    description = "Protect system availability per TSC A1.2"
    
    deny_rule {
      denied_permissions = [
        # Prevent service disruption
        "compute.instances.delete",
        "compute.instances.stop",
        "container.clusters.delete",
        "container.clusters.update",
        
        # Protect load balancers
        "compute.backendServices.delete",
        "compute.urlMaps.delete",
        "compute.targetHttpProxies.delete",
        "compute.targetHttpsProxies.delete",
        
        # Protect auto-scaling
        "compute.autoscalers.delete",
        "compute.autoscalers.update"
      ]
      
      # Only during maintenance windows
      denial_condition {
        title       = "Outside maintenance window"
        description = "Changes only allowed during maintenance"
        expression  = <<-EOT
          !(request.time.getHours() >= 2 && request.time.getHours() <= 4 && 
            request.time.getDayOfWeek() == 0)
        EOT
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# C1.2 - Confidentiality Controls
resource "google_iam_deny_policy" "soc2_confidentiality" {
  count = local.confidentiality_enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "soc2-c1-2-confidentiality"
  display_name = "SOC 2 C1.2 - Confidentiality Controls"
  
  rules {
    description = "Protect confidential information per TSC C1.2"
    
    deny_rule {
      denied_permissions = [
        # Prevent data exposure
        "storage.objects.get",
        "storage.objects.list",
        "bigquery.tables.getData",
        "bigquery.tables.export",
        
        # Prevent snapshot/backup access
        "compute.snapshots.useReadOnly",
        "compute.images.useReadOnly"
      ]
      
      # Block external access
      denial_condition {
        title       = "External access blocked"
        description = "Prevent access from outside organization"
        expression  = "!origin.ip.startsWith('10.') && !origin.ip.startsWith('172.16.')"
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# PI1.2 - Processing Integrity
resource "google_iam_deny_policy" "soc2_processing_integrity" {
  count = local.processing_integrity_enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "soc2-pi1-2-processing-integrity"
  display_name = "SOC 2 PI1.2 - Processing Integrity"
  
  rules {
    description = "Ensure processing integrity per TSC PI1.2"
    
    deny_rule {
      denied_permissions = [
        # Prevent data modification
        "bigquery.tables.updateData",
        "bigquery.tables.deleteData",
        "storage.objects.update",
        
        # Prevent pipeline changes
        "dataflow.jobs.cancel",
        "composer.environments.update",
        "cloudfunctions.functions.update"
      ]
      
      # Require change ticket
      denial_condition {
        title       = "Require change ticket"
        description = "Changes require approved ticket"
        expression  = "!request.headers['x-change-ticket'].matches('^CHG[0-9]+$')"
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# P3.2 - Privacy Controls (GDPR overlap)
resource "google_iam_deny_policy" "soc2_privacy" {
  count = local.privacy_enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "soc2-p3-2-privacy"
  display_name = "SOC 2 P3.2 - Privacy Controls"
  
  rules {
    description = "Protect personal information per TSC P3.2"
    
    deny_rule {
      denied_permissions = [
        # Prevent PII access
        "dlp.inspectFindings.list",
        "healthcare.fhirStores.read",
        "healthcare.dicomStores.read",
        
        # Prevent PII export
        "bigquery.tables.export",
        "storage.objects.create"
      ]
      
      # Restrict to privacy officers
      denial_condition {
        title       = "Privacy officer only"
        description = "Only privacy officers can access PII"
        expression  = "!('privacy-officer' in request.auth.claims.groups)"
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# Create validation rules for SOC 2 attestation
resource "google_monitoring_alert_policy" "soc2_violations" {
  count = local.security_enabled ? 1 : 0
  
  project      = var.project_id
  display_name = "SOC 2 Deny Policy Violations"
  
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
  
  notification_channels = [] # Configure based on var.monitoring_config
  
  documentation {
    content = "SOC 2 compliance control violation detected. Review the audit logs for details."
  }
}

output "soc2_controls" {
  value = {
    enabled_criteria = var.trust_criteria
    policies_created = {
      access_control       = local.security_enabled
      monitoring          = local.security_enabled
      availability        = local.availability_enabled
      confidentiality     = local.confidentiality_enabled
      processing_integrity = local.processing_integrity_enabled
      privacy             = local.privacy_enabled
    }
  }
}