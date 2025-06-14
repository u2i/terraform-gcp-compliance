# GDPR Module - Placeholder
# TODO: Implement GDPR controls

variable "project_id" { type = string }
variable "project_resource" { type = string }
variable "exception_principals" { type = list(string) }
variable "data_controller" { type = bool }
variable "special_categories" { type = bool }
variable "emergency_override" { 
  type    = bool
  default = false
}