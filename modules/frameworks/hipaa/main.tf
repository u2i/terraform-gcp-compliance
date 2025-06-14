# HIPAA Module - Placeholder
# TODO: Implement HIPAA controls

variable "project_id" { type = string }
variable "project_resource" { type = string }
variable "exception_principals" { type = list(string) }
variable "phi_present" { type = bool }
variable "emergency_override" { 
  type    = bool
  default = false
}