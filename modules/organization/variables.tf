# Variables for Organization-level Compliance Module

variable "organization_id" {
  description = "The numeric GCP organization ID"
  type        = string
  validation {
    condition     = can(regex("^[0-9]+$", var.organization_id))
    error_message = "Organization ID must be numeric."
  }
}

variable "monitoring_project_id" {
  description = "Project ID where monitoring resources (PubSub, alerts) will be created"
  type        = string
}

variable "break_glass_group" {
  description = "Google Group email for break-glass access. If not provided, will use remote state."
  type        = string
  default     = ""
}

variable "break_glass_remote_state" {
  description = "Configuration for break-glass remote state"
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

variable "additional_exception_principals" {
  description = "Additional principals to exempt from deny policies"
  type        = list(string)
  default     = []
}

variable "enable_baseline_controls" {
  description = "Enable baseline security controls (service account key restrictions)"
  type        = bool
  default     = true
}

variable "enable_audit_logging" {
  description = "Enable comprehensive audit logging at organization level"
  type        = bool
  default     = true
}

variable "enable_compliance_monitoring" {
  description = "Enable compliance monitoring with Cloud Asset Inventory"
  type        = bool
  default     = true
}

variable "enable_org_policies" {
  description = "Enable organization policy constraints"
  type        = bool
  default     = true
}

variable "restrict_service_account_creation" {
  description = "Restrict service account creation organization-wide"
  type        = bool
  default     = false
}

variable "service_account_creation_projects" {
  description = "Projects allowed to create service accounts when restricted"
  type        = list(string)
  default     = []
}

variable "restrict_external_ips" {
  description = "Restrict external IP addresses organization-wide"
  type        = bool
  default     = false
}

variable "external_ip_allowed_projects" {
  description = "Projects allowed to use external IPs when restricted"
  type        = list(string)
  default     = []
}

variable "alert_notification_channels" {
  description = "Notification channel IDs for compliance alerts"
  type        = list(string)
  default     = []
}