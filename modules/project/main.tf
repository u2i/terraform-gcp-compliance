# GCP Compliance Module - Project Level Main Configuration

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

# Determine which frameworks are enabled
locals {
  # Use provided break-glass group or fall back to remote state
  effective_break_glass_group = (
    var.break_glass_group != "" ? var.break_glass_group :
    var.break_glass_remote_state != null ? try(data.terraform_remote_state.breakglass[0].outputs.break_glass_group, "") :
    ""
  )
  
  # Validate we have a break-glass group
  has_break_glass_group = local.effective_break_glass_group != ""
  # Use simple toggles if provided, otherwise use detailed config
  iso27001_enabled = var.enable_iso27001 || try(var.compliance_frameworks.iso27001.enabled, false)
  soc2_enabled     = var.enable_soc2 || try(var.compliance_frameworks.soc2.enabled, false)
  pci_dss_enabled  = var.enable_pci_dss || try(var.compliance_frameworks.pci_dss.enabled, false)
  hipaa_enabled    = var.enable_hipaa || try(var.compliance_frameworks.hipaa.enabled, false)
  gdpr_enabled     = var.enable_gdpr || try(var.compliance_frameworks.gdpr.enabled, false)
  
  # Any framework enabled
  any_framework_enabled = local.iso27001_enabled || local.soc2_enabled || local.pci_dss_enabled || local.hipaa_enabled || local.gdpr_enabled
  
  # Compliance levels based on frameworks and data classification
  compliance_level = (
    local.hipaa_enabled || local.pci_dss_enabled || var.data_classification == "restricted" ? "maximum" :
    local.soc2_enabled || var.data_classification == "confidential" ? "high" :
    local.iso27001_enabled || var.data_classification == "internal" ? "medium" :
    "baseline"
  )
  
  # Build exception principals list
  exception_principals = concat(
    local.has_break_glass_group ? ["principalSet://goog/group/${local.effective_break_glass_group}"] : [],
    [for sa in var.compliance_exceptions.service_accounts : 
      "principal://iam.googleapis.com/projects/-/serviceAccounts/${sa}"],
    [for k, v in var.compliance_exceptions.workload_identity_pools :
      "principalSet://iam.googleapis.com/projects/${data.google_project.project.number}/locations/global/workloadIdentityPools/${v.pool_id}/attribute.${v.attribute}"]
  )
  
  # Project resource name for deny policies
  project_resource = "cloudresourcemanager.googleapis.com%2Fprojects%2F${var.project_id}"
}

# Get project details
data "google_project" "project" {
  project_id = var.project_id
}

# Log emergency override usage
resource "null_resource" "emergency_override_log" {
  count = var.emergency_override ? 1 : 0
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "WARNING: EMERGENCY OVERRIDE ACTIVATED"
      echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "Project: ${var.project_id}"
      echo "Reason: ${var.emergency_override_reason}"
      echo "User: $USER"
      echo "This action has been logged and will be audited."
      
      # Log to Cloud Logging if possible
      if command -v gcloud >/dev/null 2>&1; then
        gcloud logging write compliance-emergency \
          "Emergency override activated for project ${var.project_id}" \
          --severity=CRITICAL \
          --project="${var.project_id}" \
          --resource=global \
          --log-http || true
      fi
    EOT
  }
}

# Validate break-glass configuration
resource "null_resource" "validate_break_glass" {
  count = local.any_framework_enabled && !var.emergency_override ? 1 : 0
  
  provisioner "local-exec" {
    command = <<-EOT
      if [ -z "${local.effective_break_glass_group}" ]; then
        echo "ERROR: No break-glass group configured. Either set break_glass_group variable or configure break_glass_remote_state."
        exit 1
      fi
    EOT
  }
  
  lifecycle {
    precondition {
      condition     = local.has_break_glass_group || var.emergency_override
      error_message = "Break-glass group must be configured either directly or via remote state (unless emergency_override is true)."
    }
  }
}

# Enable required APIs based on frameworks
resource "google_project_service" "compliance_apis" {
  for_each = local.any_framework_enabled ? toset([
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "cloudkms.googleapis.com",
    "dlp.googleapis.com",
    "cloudasset.googleapis.com",
    "securitycenter.googleapis.com",
    "accesscontextmanager.googleapis.com",
    "binaryauthorization.googleapis.com"
  ]) : toset([])
  
  project = var.project_id
  service = each.key
  
  disable_dependent_services = false
  disable_on_destroy        = false
}

# Import framework-specific controls
module "iso27001_controls" {
  count  = local.iso27001_enabled ? 1 : 0
  source = "../frameworks/iso27001"
  
  project_id           = var.project_id
  project_resource     = local.project_resource
  exception_principals = local.exception_principals
  
  depends_on = [google_project_service.compliance_apis]
}

module "soc2_controls" {
  count  = local.soc2_enabled ? 1 : 0
  source = "../frameworks/soc2"
  
  project_id           = var.project_id
  project_resource     = local.project_resource
  exception_principals = local.exception_principals
  trust_criteria       = try(var.compliance_frameworks.soc2.trust_criteria, ["security"])
  
  depends_on = [google_project_service.compliance_apis]
}

module "pci_dss_controls" {
  count  = local.pci_dss_enabled ? 1 : 0
  source = "../frameworks/pci_dss"
  
  project_id           = var.project_id
  project_resource     = local.project_resource
  exception_principals = local.exception_principals
  compliance_level     = try(var.compliance_frameworks.pci_dss.level, 1)
  
  depends_on = [google_project_service.compliance_apis]
}

module "hipaa_controls" {
  count  = local.hipaa_enabled ? 1 : 0
  source = "../frameworks/hipaa"
  
  project_id           = var.project_id
  project_resource     = local.project_resource
  exception_principals = local.exception_principals
  phi_present         = try(var.compliance_frameworks.hipaa.phi_present, true)
  
  depends_on = [google_project_service.compliance_apis]
}

module "gdpr_controls" {
  count  = local.gdpr_enabled ? 1 : 0
  source = "../frameworks/gdpr"
  
  project_id           = var.project_id
  project_resource     = local.project_resource
  exception_principals = local.exception_principals
  data_controller     = try(var.compliance_frameworks.gdpr.data_controller, true)
  special_categories  = try(var.compliance_frameworks.gdpr.special_categories, false)
  
  depends_on = [google_project_service.compliance_apis]
}

# Shared controls across all frameworks
module "access_control" {
  count  = local.any_framework_enabled ? 1 : 0
  source = "../shared/access-control"
  
  project_id           = var.project_id
  project_resource     = local.project_resource
  exception_principals = local.exception_principals
  compliance_level     = local.compliance_level
  security_controls    = var.security_controls.access_control
  
  depends_on = [google_project_service.compliance_apis]
}

module "data_protection" {
  count  = local.any_framework_enabled ? 1 : 0
  source = "../shared/data-protection"
  
  project_id           = var.project_id
  project_resource     = local.project_resource
  exception_principals = local.exception_principals
  compliance_level     = local.compliance_level
  data_residency      = var.data_residency
  security_controls   = var.security_controls.data_protection
  
  depends_on = [google_project_service.compliance_apis]
}

module "audit_logging" {
  count  = local.any_framework_enabled ? 1 : 0
  source = "../shared/audit-logging"
  
  project_id           = var.project_id
  project_resource     = local.project_resource
  compliance_level     = local.compliance_level
  audit_config        = var.security_controls.audit_logging
  evidence_storage    = var.evidence_storage
  
  depends_on = [google_project_service.compliance_apis]
}

module "network_security" {
  count  = local.any_framework_enabled ? 1 : 0
  source = "../shared/network-security"
  
  project_id           = var.project_id
  project_resource     = local.project_resource
  exception_principals = local.exception_principals
  compliance_level     = local.compliance_level
  network_config      = var.security_controls.network_security
  
  depends_on = [google_project_service.compliance_apis]
}

# Compliance monitoring and reporting
module "compliance_monitoring" {
  count  = local.any_framework_enabled && var.monitoring_config.enable_compliance_dashboard ? 1 : 0
  source = "../shared/monitoring"
  
  project_id       = var.project_id
  enabled_frameworks = {
    iso27001 = local.iso27001_enabled
    soc2     = local.soc2_enabled
    pci_dss  = local.pci_dss_enabled
    hipaa    = local.hipaa_enabled
    gdpr     = local.gdpr_enabled
  }
  monitoring_config = var.monitoring_config
  
  depends_on = [google_project_service.compliance_apis]
}