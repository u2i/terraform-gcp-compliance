# Variables for Folder-level Compliance Module

variable "folder_id" {
  description = "The folder ID (folders/XXXXXXXXX format)"
  type        = string
  validation {
    condition     = can(regex("^folders/[0-9]+$", var.folder_id))
    error_message = "Folder ID must be in the format 'folders/XXXXXXXXX'."
  }
}

variable "folder_type" {
  description = "Type of folder (production, staging, development) to determine compliance level"
  type        = string
  default     = "development"
  validation {
    condition     = contains(["production", "staging", "development"], var.folder_type)
    error_message = "Folder type must be one of: production, staging, development"
  }
}

variable "monitoring_project_id" {
  description = "Project ID where monitoring resources will be created"
  type        = string
}

variable "monitoring_service_account" {
  description = "Service account used for monitoring (exempted from some audit logs)"
  type        = string
  default     = ""
}

variable "break_glass_group" {
  description = "Google Group email for break-glass access"
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

# Feature toggles
variable "enable_iam_protection" {
  description = "Enable IAM protection policies"
  type        = bool
  default     = true
}

variable "enable_resource_protection" {
  description = "Enable resource protection policies"
  type        = bool
  default     = true
}

variable "enable_service_restrictions" {
  description = "Enable service-specific restrictions"
  type        = bool
  default     = true
}

variable "enable_audit_logging" {
  description = "Enable comprehensive audit logging"
  type        = bool
  default     = true
}

variable "enable_location_restrictions" {
  description = "Enable location restrictions via org policies"
  type        = bool
  default     = false
}

variable "enable_trusted_image_projects" {
  description = "Enable trusted image project restrictions"
  type        = bool
  default     = false
}

variable "enable_compliance_monitoring" {
  description = "Enable compliance monitoring alerts"
  type        = bool
  default     = true
}

# Policy configurations
variable "allowed_locations" {
  description = "List of allowed GCP locations/regions"
  type        = list(string)
  default     = []
}

variable "trusted_image_projects" {
  description = "List of trusted projects for VM images"
  type        = list(string)
  default     = []
}