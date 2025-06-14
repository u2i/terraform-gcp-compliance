# Example: Multi-Project Compliance Deployment
# This shows how to deploy compliance to multiple projects efficiently

terraform {
  required_version = ">= 1.0"
  
  backend "gcs" {
    bucket = "tfstate-compliance-u2i"
    prefix = "multi-project"
  }
}

# Local configuration for projects
locals {
  # Define your projects and their compliance requirements
  projects = {
    "retrotool-prod" = {
      frameworks          = ["iso27001", "soc2"]
      data_classification = "confidential"
      folder_id          = "folders/123456789012"  # Production folder
    }
    
    "retrotool-staging" = {
      frameworks          = ["iso27001"]
      data_classification = "internal"
      folder_id          = "folders/123456789013"  # Staging folder
    }
    
    "analytics-prod" = {
      frameworks          = ["iso27001", "soc2", "gdpr"]
      data_classification = "restricted"  # Contains PII
      folder_id          = "folders/123456789012"
    }
    
    "ml-platform-prod" = {
      frameworks          = ["iso27001", "soc2"]
      data_classification = "confidential"
      folder_id          = "folders/123456789014"  # ML folder
    }
  }
  
  # Common configuration
  common_config = {
    break_glass_remote_state = {
      backend = "gcs"
      config = {
        bucket = "tfstate-breakglass-u2i"
        prefix = "break-glass/state"
      }
    }
    
    monitoring_project_id = "u2i-org-monitoring"
    
    # Common security controls
    base_security_controls = {
      access_control = {
        enforce_mfa                = true
        max_session_duration_hours = 12
        require_approval           = false
        approval_levels            = 1
      }
      
      audit_logging = {
        retention_days      = 2555  # 7 years
        immutable_retention = true
        export_to_siem     = true
        siem_destination   = "//storage.googleapis.com/org-audit-export"
      }
      
      network_security = {
        enforce_private_google_access = true
        allowed_ingress_ports        = ["443"]
        require_ssl                  = true
        enforce_vpc_flow_logs        = true
      }
    }
  }
}

# Deploy compliance to each project
module "project_compliance" {
  for_each = local.projects
  
  source = "github.com/u2i/terraform-gcp-compliance//modules/project?ref=v1.0.0"
  
  project_id = each.key
  
  # Use remote state for break-glass group
  break_glass_remote_state = local.common_config.break_glass_remote_state
  
  # Enable frameworks
  enable_iso27001 = contains(each.value.frameworks, "iso27001")
  enable_soc2     = contains(each.value.frameworks, "soc2")
  enable_pci_dss  = contains(each.value.frameworks, "pci_dss")
  enable_hipaa    = contains(each.value.frameworks, "hipaa")
  enable_gdpr     = contains(each.value.frameworks, "gdpr")
  
  # Data classification
  data_classification = each.value.data_classification
  
  # Security controls - merge base with classification-specific
  security_controls = {
    access_control = merge(
      local.common_config.base_security_controls.access_control,
      each.value.data_classification == "restricted" ? {
        require_approval = true
        approval_levels  = 2
        max_session_duration_hours = 4
      } : {}
    )
    
    data_protection = {
      enforce_encryption = true
      enforce_dlp       = each.value.data_classification != "public"
      allowed_kms_locations = ["us-central1", "us-east1"]
    }
    
    audit_logging = local.common_config.base_security_controls.audit_logging
    
    network_security = local.common_config.base_security_controls.network_security
  }
  
  # Monitoring
  monitoring_config = {
    enable_compliance_dashboard = true
    compliance_scan_schedule   = "0 */4 * * *"
  }
  
  # Evidence storage
  evidence_storage = {
    enabled        = true
    bucket_name    = "${each.key}-compliance-evidence"
    retention_days = 2555
    storage_class  = "STANDARD"
  }
}

# Create evidence buckets
resource "google_storage_bucket" "evidence" {
  for_each = local.projects
  
  name     = "${each.key}-compliance-evidence"
  location = "US"
  project  = each.key
  
  uniform_bucket_level_access = true
  
  retention_policy {
    retention_period = 2555 * 86400  # 7 years
    is_locked       = each.value.data_classification == "restricted"
  }
  
  versioning {
    enabled = true
  }
  
  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }
}

# Create monitoring dashboard for all projects
resource "google_monitoring_dashboard" "compliance_overview" {
  project        = local.common_config.monitoring_project_id
  dashboard_json = jsonencode({
    displayName = "Compliance Overview - All Projects"
    mosaicLayout = {
      columns = 12
      tiles = concat(
        # Header
        [{
          width  = 12
          height = 2
          widget = {
            text = {
              content = "# Compliance Overview\nMonitoring ${length(local.projects)} projects"
              format  = "MARKDOWN"
            }
          }
        }],
        # Per-project tiles
        [for idx, project in keys(local.projects) : {
          xPos   = (idx % 3) * 4
          yPos   = 2 + floor(idx / 3) * 4
          width  = 4
          height = 4
          widget = {
            title = project
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "resource.type=\"global\" AND metric.type=\"logging.googleapis.com/user/compliance_violations\" AND resource.label.project_id=\"${project}\""
                  aggregation = {
                    alignmentPeriod    = "3600s"
                    perSeriesAligner   = "ALIGN_COUNT"
                    crossSeriesReducer = "REDUCE_SUM"
                  }
                }
              }
              sparkChartView = {
                sparkChartType = "SPARK_LINE"
              }
            }
          }
        }]
      )
    }
  })
}

# Outputs
output "deployed_projects" {
  description = "Projects with compliance deployed"
  value       = keys(local.projects)
}

output "compliance_status" {
  description = "Compliance status for each project"
  value = {
    for project, config in module.project_compliance :
    project => {
      frameworks = config.enabled_frameworks
      level      = local.projects[project].data_classification
      dashboard  = config.dashboard_url
    }
  }
}

output "evidence_buckets" {
  description = "Evidence storage buckets created"
  value = {
    for project, bucket in google_storage_bucket.evidence :
    project => bucket.url
  }
}

output "monitoring_dashboard" {
  description = "URL to the compliance overview dashboard"
  value       = "https://console.cloud.google.com/monitoring/dashboards/custom/${google_monitoring_dashboard.compliance_overview.id}?project=${local.common_config.monitoring_project_id}"
}