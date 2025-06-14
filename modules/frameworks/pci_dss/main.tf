# PCI DSS Module - Placeholder
# TODO: Implement PCI DSS controls

variable "project_id" { type = string }
variable "project_resource" { type = string }
variable "exception_principals" { type = list(string) }
variable "compliance_level" { type = number }
variable "emergency_override" { 
  type    = bool
  default = false
}