# GCP Compliance Module - Folder Level
# Implements folder-wide compliance controls for hierarchical policy enforcement

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

# Get folder details
data "google_folder" "folder" {
  folder = var.folder_id
}

locals {
  # Use provided break-glass group or fall back to remote state
  effective_break_glass_group = (
    var.break_glass_group != "" ? var.break_glass_group :
    var.break_glass_remote_state != null ? try(data.terraform_remote_state.breakglass[0].outputs.break_glass_group, "") :
    ""
  )
  
  # Folder resource for deny policies
  folder_resource = "cloudresourcemanager.googleapis.com%2Ffolders%2F${data.google_folder.folder.folder_id}"
  
  # Exception principals
  exception_principals = concat(
    ["principalSet://goog/group/${local.effective_break_glass_group}"],
    var.additional_exception_principals
  )
  
  # Determine compliance level based on folder type
  compliance_level = (
    var.folder_type == "production" ? "high" :
    var.folder_type == "staging" ? "medium" :
    "baseline"
  )
}

# Folder-level IAM protection
resource "google_iam_deny_policy" "folder_iam_protection" {
  count = var.enable_iam_protection ? 1 : 0
  
  parent       = local.folder_resource
  name         = "folder-compliance-iam-protection"
  display_name = "Folder Compliance - IAM Protection"
  
  rules {
    description = "Protect IAM configuration at folder level"
    
    deny_rule {
      denied_permissions = [
        # Prevent unauthorized IAM changes
        "resourcemanager.folders.setIamPolicy",
        "resourcemanager.projects.setIamPolicy",
        "iam.serviceAccounts.setIamPolicy",
        
        # Prevent role modifications
        "iam.roles.create",
        "iam.roles.update",
        "iam.roles.delete"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = local.exception_principals
    }
  }
}

# Folder-level resource protection
resource "google_iam_deny_policy" "folder_resource_protection" {
  count = var.enable_resource_protection ? 1 : 0
  
  parent       = local.folder_resource
  name         = "folder-compliance-resource-protection"
  display_name = "Folder Compliance - Resource Protection"
  
  rules {
    description = "Protect critical resources at folder level"
    
    deny_rule {
      denied_permissions = [
        # Prevent folder/project deletion
        "resourcemanager.folders.delete",
        "resourcemanager.projects.delete",
        
        # Prevent moving resources
        "resourcemanager.folders.move",
        "resourcemanager.projects.move"
      ]
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = local.exception_principals
    }
  }
}

# Folder-level service restrictions
resource "google_iam_deny_policy" "folder_service_restrictions" {
  count = var.enable_service_restrictions && local.compliance_level != "baseline" ? 1 : 0
  
  parent       = local.folder_resource
  name         = "folder-compliance-service-restrictions"
  display_name = "Folder Compliance - Service Restrictions"
  
  rules {
    description = "Restrict high-risk services at folder level"
    
    deny_rule {
      denied_permissions = [
        # Restrict dangerous compute operations
        "compute.instances.setServiceAccount",
        "compute.instances.setMetadata",
        
        # Restrict data exports
        "bigquery.tables.export",
        "storage.buckets.setIamPolicy"
      ]
      
      # Apply based on compliance level
      denial_condition {
        title       = "High-risk operations restricted"
        description = "Operations restricted based on folder compliance level"
        expression  = local.compliance_level == "high" ? "true" : "!request.auth.access_levels.exists(l, l == 'approved_operation')"
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = local.exception_principals
    }
  }
}

# Folder organization policies
resource "google_org_policy_policy" "folder_allowed_locations" {
  count = var.enable_location_restrictions && length(var.allowed_locations) > 0 ? 1 : 0
  
  name   = "${data.google_folder.folder.name}/policies/gcp.resourceLocations"
  parent = data.google_folder.folder.name
  
  spec {
    rules {
      values {
        allowed_values = var.allowed_locations
      }
    }
  }
}

resource "google_org_policy_policy" "folder_trusted_image_projects" {
  count = var.enable_trusted_image_projects && length(var.trusted_image_projects) > 0 ? 1 : 0
  
  name   = "${data.google_folder.folder.name}/policies/compute.trustedImageProjects"
  parent = data.google_folder.folder.name
  
  spec {
    rules {
      values {
        allowed_values = var.trusted_image_projects
      }
    }
  }
}

resource "google_org_policy_policy" "folder_allowed_ingress_settings" {
  count = var.folder_type == "production" ? 1 : 0
  
  name   = "${data.google_folder.folder.name}/policies/cloudfunctions.allowedIngressSettings"
  parent = data.google_folder.folder.name
  
  spec {
    rules {
      values {
        # Only allow internal and Cloud Load Balancing traffic for production
        allowed_values = ["ALLOW_INTERNAL_AND_GCLB"]
      }
    }
  }
}

# Folder-level audit configuration
resource "google_folder_iam_audit_config" "folder_audit_logs" {
  count = var.enable_audit_logging ? 1 : 0
  
  folder  = data.google_folder.folder.folder_id
  service = "allServices"
  
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  
  audit_log_config {
    log_type = "DATA_READ"
    
    # Exempt some data reads for performance in non-production
    dynamic "exempted_members" {
      for_each = local.compliance_level != "high" ? ["serviceAccount:${var.monitoring_service_account}"] : []
      content {
        member = exempted_members.value
      }
    }
  }
  
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# Monitoring for folder compliance
resource "google_monitoring_alert_policy" "folder_compliance_violations" {
  count = var.enable_compliance_monitoring ? 1 : 0
  
  project      = var.monitoring_project_id
  display_name = "Folder ${var.folder_id} - Compliance Violations"
  
  conditions {
    display_name = "Folder Policy Violation"
    
    condition_matched_log {
      filter = <<-EOT
        protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
        AND protoPayload.status.code=7
        AND protoPayload.status.message=~"Denied by IAM deny policy"
        AND protoPayload.resourceName=~"folders/${data.google_folder.folder.folder_id}"
      EOT
    }
  }
  
  documentation {
    content = "Compliance violation detected in folder ${var.folder_id} (${var.folder_type})"
  }
}