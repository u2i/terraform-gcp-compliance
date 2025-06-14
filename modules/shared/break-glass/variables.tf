# Variables for Break-glass Integration Module

variable "break_glass_group" {
  description = "Email of the break-glass group (overrides remote state)"
  type        = string
  default     = ""
}

variable "use_remote_state" {
  description = "Whether to use remote state to get break-glass configuration"
  type        = bool
  default     = true
}

variable "remote_state_backend" {
  description = "Backend type for remote state (e.g., 'gcs')"
  type        = string
  default     = "gcs"
}

variable "remote_state_config" {
  description = "Configuration for remote state backend"
  type        = map(string)
  default = {
    bucket = "tfstate-breakglass-u2i"
    prefix = "break-glass/state"
  }
}

variable "additional_exception_principals" {
  description = "Additional principals to include in exception lists"
  type        = list(string)
  default     = []
}

variable "require_break_glass" {
  description = "Whether to require break-glass configuration (fails if not configured)"
  type        = bool
  default     = true
}

variable "validate_group" {
  description = "Whether to validate the break-glass group exists in Google Workspace"
  type        = bool
  default     = false
}

variable "monitoring_project_id" {
  description = "Project ID for monitoring resources (dashboards, alerts)"
  type        = string
  default     = ""
}

variable "create_monitoring_dashboard" {
  description = "Whether to create a break-glass monitoring dashboard"
  type        = bool
  default     = true
}

variable "create_usage_alerts" {
  description = "Whether to create alerts for break-glass usage"
  type        = bool
  default     = true
}

variable "alert_notification_channels" {
  description = "Notification channel IDs for break-glass alerts"
  type        = list(string)
  default     = []
}