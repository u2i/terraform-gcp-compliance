# Complete Example - Multi-Framework Compliance

module "compliance" {
  source = "../../modules/project"
  
  project_id        = "my-secure-project"
  break_glass_group = "break-glass@company.com"
  
  # Enable multiple frameworks
  compliance_frameworks = {
    iso27001 = {
      enabled = true
      level   = "high"
    }
    soc2 = {
      enabled        = true
      trust_criteria = ["security", "availability", "confidentiality"]
    }
    pci_dss = {
      enabled = true
      level   = 1  # Level 1 merchant
    }
    gdpr = {
      enabled            = true
      data_controller    = true
      special_categories = true  # Health data
    }
  }
  
  # Highest data classification
  data_classification = "restricted"
  
  # EU data residency for GDPR
  data_residency = {
    enabled = true
    regions = ["europe-west1", "europe-west4"]
  }
  
  # Security controls
  security_controls = {
    access_control = {
      enforce_mfa                = true
      max_session_duration_hours = 8
      require_approval           = true
      approval_levels            = 2
    }
    
    data_protection = {
      enforce_encryption = true
      enforce_dlp       = true
      allowed_kms_locations = ["europe-west1", "europe-west4"]
    }
    
    audit_logging = {
      retention_days      = 2555  # 7 years
      immutable_retention = true
      export_to_siem     = true
      siem_destination   = "//storage.googleapis.com/audit-export-bucket"
    }
    
    network_security = {
      enforce_private_google_access = true
      allowed_ingress_ports        = ["443"]
      require_ssl                  = true
      enforce_vpc_flow_logs        = true
    }
  }
  
  # Exceptions for CI/CD
  compliance_exceptions = {
    service_accounts = [
      "terraform@my-secure-project.iam.gserviceaccount.com",
      "github-actions@my-secure-project.iam.gserviceaccount.com"
    ]
    
    workload_identity_pools = {
      github = {
        pool_id     = "github-pool"
        provider_id = "github"
        attribute   = "repository/myorg/myrepo"
      }
    }
  }
  
  # Integrations
  integrations = {
    siem = {
      enabled        = true
      provider       = "splunk"
      endpoint       = "https://splunk.company.com:8088"
      api_key_secret = "projects/my-secure-project/secrets/splunk-hec-token/versions/latest"
    }
    
    ticketing = {
      enabled     = true
      provider    = "servicenow"
      endpoint    = "https://company.service-now.com"
      project_key = "COMPLIANCE"
    }
  }
  
  # Monitoring
  monitoring_config = {
    enable_compliance_dashboard = true
    alert_channels = [
      {
        type   = "email"
        target = "security-team@company.com"
      },
      {
        type   = "pagerduty"
        target = "security-incidents"
      }
    ]
    compliance_scan_schedule = "0 */4 * * *"  # Every 4 hours
  }
}

# Create required infrastructure
resource "google_storage_bucket" "audit_export" {
  name     = "audit-export-bucket"
  location = "EU"
  
  uniform_bucket_level_access = true
  
  retention_policy {
    retention_period = 2555 * 86400  # 7 years in seconds
    is_locked       = true
  }
}

# Outputs for compliance reporting
output "compliance_status" {
  value = module.compliance.compliance_status
}

output "enabled_frameworks" {
  value = module.compliance.enabled_frameworks
}

output "compliance_report_url" {
  value = module.compliance.dashboard_url
}