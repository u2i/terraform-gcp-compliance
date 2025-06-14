# ISO 27001:2022 Compliance Controls
# Implements information security management system requirements

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

variable "data_classification" {
  type    = string
  default = "internal"
}

variable "emergency_override" {
  type    = bool
  default = false
}

locals {
  # Stricter controls for higher classification
  is_high_security = var.data_classification == "confidential" || var.data_classification == "restricted"
}

# A.9 - Access Control
resource "google_iam_deny_policy" "iso27001_access_control" {
  count = var.emergency_override ? 0 : 1
  
  parent       = var.project_resource
  name         = "iso27001-a9-access-control"
  display_name = "ISO 27001 A.9 - Access Control"
  
  rules {
    description = "Enforce access control requirements per ISO 27001 A.9"
    
    deny_rule {
      denied_permissions = [
        # A.9.1 - Business requirements for access control
        "resourcemanager.projects.setIamPolicy",
        "iam.serviceAccounts.setIamPolicy",
        
        # A.9.2 - User access management
        "iam.serviceAccounts.create",
        "iam.serviceAccountKeys.create",
        "iam.serviceAccountKeys.delete",
        
        # A.9.4 - Access to systems and applications
        "compute.instances.setMetadata",
        "compute.projects.setCommonInstanceMetadata"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# A.10 - Cryptography
resource "google_iam_deny_policy" "iso27001_cryptography" {
  count = var.emergency_override ? 0 : 1
  
  parent       = var.project_resource
  name         = "iso27001-a10-cryptography"
  display_name = "ISO 27001 A.10 - Cryptography"
  
  rules {
    description = "Enforce cryptographic controls per ISO 27001 A.10"
    
    deny_rule {
      denied_permissions = [
        # A.10.1 - Cryptographic controls
        "cloudkms.cryptoKeys.create",
        "cloudkms.cryptoKeys.update",
        "cloudkms.cryptoKeyVersions.destroy",
        
        # Prevent disabling encryption
        "compute.disks.create",
        "storage.buckets.create"
      ]
      
      # Only allow with proper encryption
      denial_condition {
        title       = "Require encryption"
        description = "Resources must be encrypted"
        expression  = "!resource.labels.encryption_enabled"
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# A.12 - Operations Security
resource "google_iam_deny_policy" "iso27001_operations" {
  count = var.emergency_override ? 0 : 1
  
  parent       = var.project_resource
  name         = "iso27001-a12-operations"
  display_name = "ISO 27001 A.12 - Operations Security"
  
  rules {
    description = "Enforce operations security per ISO 27001 A.12"
    
    deny_rule {
      denied_permissions = [
        # A.12.1 - Operational procedures
        "compute.instances.delete",
        "container.clusters.delete",
        
        # A.12.4 - Logging and monitoring
        "logging.sinks.delete",
        "logging.sinks.update",
        "monitoring.alertPolicies.delete",
        
        # A.12.6 - Technical vulnerability management
        "compute.securityPolicies.delete",
        "compute.firewalls.delete"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# A.13 - Communications Security
resource "google_iam_deny_policy" "iso27001_communications" {
  count = !var.emergency_override && local.is_high_security ? 1 : 0
  
  parent       = var.project_resource
  name         = "iso27001-a13-communications"
  display_name = "ISO 27001 A.13 - Communications Security"
  
  rules {
    description = "Enforce communications security per ISO 27001 A.13"
    
    deny_rule {
      denied_permissions = [
        # A.13.1 - Network security management
        "compute.networks.delete",
        "compute.subnetworks.delete",
        "compute.routers.delete",
        
        # A.13.2 - Information transfer
        "storage.objects.create",
        "bigquery.tables.export"
      ]
      
      # Block external transfers
      denial_condition {
        title       = "Internal only"
        description = "Block external data transfers"
        expression  = "destination.ip != '10.0.0.0/8' && destination.ip != '172.16.0.0/12'"
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# A.14 - System Development
resource "google_iam_deny_policy" "iso27001_development" {
  count = var.emergency_override ? 0 : 1
  
  parent       = var.project_resource
  name         = "iso27001-a14-development"
  display_name = "ISO 27001 A.14 - System Development"
  
  rules {
    description = "Enforce secure development per ISO 27001 A.14"
    
    deny_rule {
      denied_permissions = [
        # A.14.2 - Security in development
        "cloudfunctions.functions.create",
        "cloudfunctions.functions.update",
        "run.services.create",
        "run.services.update",
        
        # A.14.3 - Test data
        "bigquery.tables.getData"
      ]
      
      # Require security review
      denial_condition {
        title       = "Security review required"
        description = "Deployments require security review"
        expression  = "!request.headers['x-security-review'].matches('^SEC-[0-9]+$')"
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# A.16 - Incident Management
resource "google_iam_deny_policy" "iso27001_incident" {
  count = var.emergency_override ? 0 : 1
  
  parent       = var.project_resource
  name         = "iso27001-a16-incident"
  display_name = "ISO 27001 A.16 - Incident Management"
  
  rules {
    description = "Protect incident response capabilities per ISO 27001 A.16"
    
    deny_rule {
      denied_permissions = [
        # Protect forensic capabilities
        "logging.logs.delete",
        "compute.snapshots.delete",
        "storage.objects.delete",
        
        # Protect incident response tools
        "monitoring.alertPolicies.update",
        "monitoring.notificationChannels.delete"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

# A.18 - Compliance
resource "google_iam_deny_policy" "iso27001_compliance" {
  count = var.emergency_override ? 0 : 1
  
  parent       = var.project_resource
  name         = "iso27001-a18-compliance"
  display_name = "ISO 27001 A.18 - Compliance"
  
  rules {
    description = "Maintain compliance capabilities per ISO 27001 A.18"
    
    deny_rule {
      denied_permissions = [
        # A.18.1 - Compliance with legal requirements
        "resourcemanager.projects.undelete",
        "cloudkms.cryptoKeyVersions.restore",
        
        # A.18.2 - Information security reviews
        "securitycenter.findings.setState",
        "cloudasset.assets.delete"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}

output "iso27001_controls" {
  value = {
    emergency_override = var.emergency_override
    access_control     = !var.emergency_override
    cryptography       = !var.emergency_override
    operations         = !var.emergency_override
    communications     = !var.emergency_override && local.is_high_security
    development        = !var.emergency_override
    incident_response  = !var.emergency_override
    compliance         = !var.emergency_override
  }
}