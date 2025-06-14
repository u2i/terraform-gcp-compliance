# Outputs for the GCP Compliance Project Module

output "project_id" {
  description = "The project ID where compliance controls are applied"
  value       = var.project_id
}

output "enabled_frameworks" {
  description = "Map of enabled compliance frameworks"
  value = {
    iso27001 = local.iso27001_enabled
    soc2     = local.soc2_enabled
    pci_dss  = local.pci_dss_enabled
    hipaa    = local.hipaa_enabled
    gdpr     = local.gdpr_enabled
  }
}

output "compliance_level" {
  description = "The determined compliance level based on enabled frameworks"
  value       = local.compliance_level
}

output "compliance_status" {
  description = "Detailed compliance status for each framework"
  value = {
    iso27001 = local.iso27001_enabled ? {
      enabled  = true
      controls = try(module.iso27001_controls[0].iso27001_controls, {})
    } : { enabled = false }
    
    soc2 = local.soc2_enabled ? {
      enabled  = true
      criteria = try(var.compliance_frameworks.soc2.trust_criteria, ["security"])
      controls = try(module.soc2_controls[0].soc2_controls, {})
    } : { enabled = false }
    
    pci_dss = local.pci_dss_enabled ? {
      enabled = true
      level   = try(var.compliance_frameworks.pci_dss.level, 1)
    } : { enabled = false }
    
    hipaa = local.hipaa_enabled ? {
      enabled     = true
      phi_present = try(var.compliance_frameworks.hipaa.phi_present, true)
    } : { enabled = false }
    
    gdpr = local.gdpr_enabled ? {
      enabled            = true
      data_controller    = try(var.compliance_frameworks.gdpr.data_controller, true)
      special_categories = try(var.compliance_frameworks.gdpr.special_categories, false)
    } : { enabled = false }
  }
}

output "security_controls" {
  description = "Applied security controls configuration"
  value = {
    access_control = try(module.access_control[0].access_control_policies, {})
    data_protection = {
      encryption_enforced = true
      dlp_enabled        = var.security_controls.data_protection.enforce_dlp
      data_residency     = var.data_residency.enabled
    }
    audit_logging = {
      enabled             = true
      retention_days      = var.security_controls.audit_logging.retention_days
      immutable_retention = var.security_controls.audit_logging.immutable_retention
    }
    network_security = {
      private_google_access = var.security_controls.network_security.enforce_private_google_access
      ssl_enforced         = var.security_controls.network_security.require_ssl
    }
  }
}

output "exception_principals" {
  description = "List of principals exempted from deny policies"
  value       = local.exception_principals
  sensitive   = true
}

output "deny_policy_count" {
  description = "Total number of deny policies created"
  value = sum([
    local.iso27001_enabled ? 7 : 0,  # ISO 27001 policies
    local.soc2_enabled ? 6 : 0,       # SOC 2 policies
    local.pci_dss_enabled ? 5 : 0,    # PCI DSS policies
    local.hipaa_enabled ? 6 : 0,      # HIPAA policies
    local.gdpr_enabled ? 5 : 0,       # GDPR policies
    local.any_framework_enabled ? 5 : 0  # Shared policies
  ])
}

output "dashboard_url" {
  description = "URL to the compliance monitoring dashboard"
  value = local.any_framework_enabled && var.monitoring_config.enable_compliance_dashboard ? (
    "https://console.cloud.google.com/monitoring/dashboards/custom/${var.project_id}-compliance"
  ) : null
}

output "evidence_storage" {
  description = "Evidence storage configuration for compliance audits"
  value = try(var.evidence_storage.enabled, true) ? {
    bucket_name     = var.evidence_storage.bucket_name
    retention_days  = var.evidence_storage.retention_days
    storage_class   = var.evidence_storage.storage_class
  } : null
}

output "compliance_report" {
  description = "Summary report for compliance attestation"
  value = {
    generated_at = timestamp()
    project_id   = var.project_id
    frameworks   = compact([
      local.iso27001_enabled ? "iso27001" : "",
      local.soc2_enabled ? "soc2" : "",
      local.pci_dss_enabled ? "pci_dss" : "",
      local.hipaa_enabled ? "hipaa" : "",
      local.gdpr_enabled ? "gdpr" : ""
    ])
    controls = {
      total_policies = sum([
        local.iso27001_enabled ? 7 : 0,
        local.soc2_enabled ? 6 : 0,
        local.pci_dss_enabled ? 5 : 0,
        local.hipaa_enabled ? 6 : 0,
        local.gdpr_enabled ? 5 : 0,
        local.any_framework_enabled ? 5 : 0
      ])
      access_control = local.any_framework_enabled
      data_protection = local.any_framework_enabled
      audit_logging = local.any_framework_enabled
      network_security = local.any_framework_enabled
      incident_response = local.any_framework_enabled
    }
    data_residency = var.data_residency.enabled ? {
      restricted_regions = var.data_residency.regions
    } : null
    next_review_date = timeadd(timestamp(), "2160h")  # 90 days
  }
}

output "implementation_notes" {
  description = "Important notes about the compliance implementation"
  value = {
    emergency_override_active = var.emergency_override
    emergency_override_reason = var.emergency_override ? var.emergency_override_reason : null
    break_glass_configured = local.has_break_glass_group
    workload_identity_configured = length(var.compliance_exceptions.workload_identity_pools) > 0
    monitoring_enabled = var.monitoring_config.enable_compliance_dashboard
    evidence_collection_enabled = try(var.evidence_storage.enabled, true)
    frameworks_requiring_attestation = compact([
      local.iso27001_enabled ? "ISO 27001 - Annual audit required" : "",
      local.soc2_enabled ? "SOC 2 - Type II audit required" : "",
      local.pci_dss_enabled ? "PCI DSS - Quarterly scans required" : "",
      local.hipaa_enabled ? "HIPAA - Risk assessment required" : "",
      local.gdpr_enabled ? "GDPR - DPO assignment required" : ""
    ])
    warnings = compact([
      var.emergency_override ? "WARNING: Emergency override is active - all deny policies disabled!" : ""
    ])
  }
}