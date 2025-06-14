# GCP Compliance Module - Project Level Variables

variable "project_id" {
  description = "The GCP project ID where compliance controls will be applied"
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must be a valid GCP project identifier."
  }
}

variable "break_glass_group" {
  description = "Google Group email that will be exempted from deny policies for emergency access. If not provided, will attempt to use organization-wide break-glass group from remote state."
  type        = string
  default     = ""
  validation {
    condition     = var.break_glass_group == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.break_glass_group))
    error_message = "Break glass group must be a valid email address or empty to use remote state."
  }
}

# Remote state configuration for break-glass integration
variable "break_glass_remote_state" {
  description = "Configuration for break-glass remote state. Set to null to disable remote state lookup."
  type = object({
    backend = string
    config  = map(string)
  })
  default = {
    backend = "gcs"
    config = {
      bucket = "tfstate-breakglass-u2i"
      prefix = "break-glass/state"
    }
  }
}

# Compliance Framework Toggles
variable "enable_iso27001" {
  description = "Enable ISO 27001:2022 compliance controls"
  type        = bool
  default     = false
}

variable "enable_soc2" {
  description = "Enable SOC 2 Type II compliance controls"
  type        = bool
  default     = false
}

variable "enable_pci_dss" {
  description = "Enable PCI DSS compliance controls"
  type        = bool
  default     = false
}

variable "enable_hipaa" {
  description = "Enable HIPAA compliance controls"
  type        = bool
  default     = false
}

variable "enable_gdpr" {
  description = "Enable GDPR compliance controls"
  type        = bool
  default     = false
}

# Advanced Framework Configuration
variable "compliance_frameworks" {
  description = "Detailed compliance framework configuration"
  type = object({
    iso27001 = optional(object({
      enabled = bool
      level   = optional(string, "high") # high, medium, low
    }), { enabled = false })
    
    soc2 = optional(object({
      enabled        = bool
      trust_criteria = optional(list(string), ["security"])
      # Options: security, availability, processing_integrity, confidentiality, privacy
    }), { enabled = false })
    
    pci_dss = optional(object({
      enabled = bool
      level   = optional(number, 1) # 1-4 based on transaction volume
    }), { enabled = false })
    
    hipaa = optional(object({
      enabled     = bool
      phi_present = optional(bool, true)
    }), { enabled = false })
    
    gdpr = optional(object({
      enabled               = bool
      data_controller       = optional(bool, true)
      data_processor        = optional(bool, false)
      special_categories    = optional(bool, false)
    }), { enabled = false })
  })
  default = {}
}

# Data Classification
variable "data_classification" {
  description = "Highest level of data classification in the project"
  type        = string
  default     = "internal"
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}

# Security Controls
variable "security_controls" {
  description = "Fine-grained security control configuration"
  type = object({
    access_control = optional(object({
      enforce_mfa                = optional(bool, true)
      max_session_duration_hours = optional(number, 12)
      require_approval           = optional(bool, true)
      approval_levels            = optional(number, 1)
    }), {})
    
    data_protection = optional(object({
      enforce_encryption     = optional(bool, true)
      enforce_dlp           = optional(bool, false)
      allowed_kms_locations = optional(list(string), [])
    }), {})
    
    audit_logging = optional(object({
      retention_days           = optional(number, 2555) # 7 years
      immutable_retention     = optional(bool, true)
      export_to_siem          = optional(bool, false)
      siem_destination        = optional(string, "")
    }), {})
    
    network_security = optional(object({
      enforce_private_google_access = optional(bool, true)
      allowed_ingress_ports        = optional(list(string), ["443"])
      require_ssl                  = optional(bool, true)
      enforce_vpc_flow_logs        = optional(bool, true)
    }), {})
  })
  default = {}
}

# Data Residency
variable "data_residency" {
  description = "Data residency requirements"
  type = object({
    enabled = bool
    regions = list(string)
  })
  default = {
    enabled = false
    regions = []
  }
}

# Exceptions and Exemptions
variable "compliance_exceptions" {
  description = "Service accounts and workload identities exempt from compliance controls"
  type = object({
    service_accounts = optional(list(string), [])
    workload_identity_pools = optional(map(object({
      pool_id     = string
      provider_id = string
      attribute   = string
    })), {})
    temporary_exemptions = optional(list(object({
      principal   = string
      expiry_date = string
      reason      = string
    })), [])
  })
  default = {}
}

# Integration Points
variable "integrations" {
  description = "External system integrations"
  type = object({
    siem = optional(object({
      enabled      = bool
      provider     = string # splunk, datadog, elastic, chronicle
      endpoint     = string
      api_key_secret = string
    }), { enabled = false })
    
    ticketing = optional(object({
      enabled  = bool
      provider = string # servicenow, jira, github
      endpoint = string
      project_key = string
    }), { enabled = false })
    
    vault = optional(object({
      enabled  = bool
      provider = string # hashicorp, google_secret_manager
      endpoint = string
    }), { enabled = false })
  })
  default = {}
}

# Monitoring and Alerting
# Emergency override - USE WITH EXTREME CAUTION
variable "emergency_override" {
  description = "EMERGENCY USE ONLY: Disables all deny policies. This should only be used in critical situations where deny policies are preventing emergency remediation."
  type        = bool
  default     = false
  
  validation {
    condition     = !var.emergency_override || can(regex("^true$", tostring(var.emergency_override)))
    error_message = "Emergency override must be explicitly set to true. This is a dangerous operation."
  }
}

variable "emergency_override_reason" {
  description = "Required when emergency_override is true. Must provide a reason for the override."
  type        = string
  default     = ""
  
  validation {
    condition     = !var.emergency_override || (var.emergency_override && length(var.emergency_override_reason) > 10)
    error_message = "When emergency_override is true, you must provide a detailed reason (>10 characters)."
  }
}

variable "monitoring_config" {
  description = "Monitoring and alerting configuration"
  type = object({
    enable_compliance_dashboard = optional(bool, true)
    alert_channels = optional(list(object({
      type  = string # email, sms, slack, pagerduty
      target = string
    })), [])
    compliance_scan_schedule = optional(string, "0 9 * * 1") # Weekly on Monday 9am
  })
  default = {}
}

# Cost Optimization
variable "cost_controls" {
  description = "Cost control measures"
  type = object({
    enable_budget_alerts      = optional(bool, true)
    monthly_budget_amount    = optional(number, 0)
    enable_recommendations   = optional(bool, true)
    auto_delete_unused      = optional(bool, false)
  })
  default = {}
}

# Tags
variable "labels" {
  description = "Labels to apply to all resources"
  type        = map(string)
  default = {
    managed_by = "terraform"
    module     = "gcp-compliance"
  }
}

# Compliance Evidence
variable "evidence_storage" {
  description = "Configuration for compliance evidence storage"
  type = object({
    bucket_name     = optional(string, "")
    retention_years = optional(number, 7)
    access_logs     = optional(bool, true)
  })
  default = {}
}