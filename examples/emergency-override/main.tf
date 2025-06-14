# Example: Emergency Override Usage
# This shows how to temporarily disable compliance controls in an emergency

terraform {
  required_version = ">= 1.0"
}

# IMPORTANT: Emergency override should ONLY be used in critical situations
# where compliance controls are preventing emergency remediation.
#
# Process:
# 1. Document the incident requiring override
# 2. Get approval from security team
# 3. Apply this configuration
# 4. Fix the emergency
# 5. IMMEDIATELY remove the override
# 6. Document actions taken
# 7. Post-incident review

module "project_compliance_emergency" {
  source = "github.com/u2i/terraform-gcp-compliance//modules/project?ref=v1.0.0"
  
  project_id = "critical-production-project"
  
  # Normal configuration
  enable_iso27001 = true
  enable_soc2     = true
  
  data_classification = "confidential"
  
  # EMERGENCY OVERRIDE - REMOVE IMMEDIATELY AFTER USE
  emergency_override = true
  emergency_override_reason = "Critical incident #INC-2024-001 - Database corruption preventing customer access. Approved by: security-oncall@company.com at 2024-01-15 03:45 UTC"
  
  # The rest of configuration remains the same
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
      allowed_kms_locations = ["us-central1"]
    }
    
    audit_logging = {
      retention_days      = 2555
      immutable_retention = true
      export_to_siem     = true
      siem_destination   = "//storage.googleapis.com/audit-export"
    }
    
    network_security = {
      enforce_private_google_access = true
      allowed_ingress_ports        = ["443"]
      require_ssl                  = true
      enforce_vpc_flow_logs        = true
    }
  }
}

# Alert when emergency override is active
resource "google_monitoring_alert_policy" "emergency_override_active" {
  project      = "critical-production-project"
  display_name = "CRITICAL: Emergency Override Active"
  
  conditions {
    display_name = "Emergency override is enabled"
    
    condition_matched_log {
      filter = <<-EOT
        resource.type="global"
        severity="CRITICAL"
        textPayload=~"Emergency override activated"
      EOT
    }
  }
  
  alert_strategy {
    auto_close = "3600s"  # Auto-close after 1 hour
  }
  
  documentation {
    content = <<-EOT
      EMERGENCY OVERRIDE IS ACTIVE!
      
      Project: ${module.project_compliance_emergency.project_id}
      Reason: ${module.project_compliance_emergency.implementation_notes.emergency_override_reason}
      
      This should be removed immediately after the emergency is resolved.
    EOT
  }
  
  notification_channels = [
    # Add your critical alert channels here
  ]
}

# Log the override activation
resource "null_resource" "log_override" {
  triggers = {
    override_active = module.project_compliance_emergency.implementation_notes.emergency_override_active
  }
  
  provisioner "local-exec" {
    command = <<-EOT
      if [ "${module.project_compliance_emergency.implementation_notes.emergency_override_active}" = "true" ]; then
        echo "EMERGENCY OVERRIDE ACTIVATED" | tee -a emergency-override.log
        echo "Timestamp: $(date -u)" | tee -a emergency-override.log
        echo "Project: critical-production-project" | tee -a emergency-override.log
        echo "Reason: ${module.project_compliance_emergency.implementation_notes.emergency_override_reason}" | tee -a emergency-override.log
        echo "---" | tee -a emergency-override.log
        
        # Send to security team
        # curl -X POST https://security-webhook.company.com/emergency-override \
        #   -H "Content-Type: application/json" \
        #   -d '{"project": "critical-production-project", "active": true}'
      fi
    EOT
  }
}

output "emergency_status" {
  value = {
    override_active = module.project_compliance_emergency.implementation_notes.emergency_override_active
    reason         = module.project_compliance_emergency.implementation_notes.emergency_override_reason
    warnings       = module.project_compliance_emergency.implementation_notes.warnings
  }
}

output "next_steps" {
  value = module.project_compliance_emergency.implementation_notes.emergency_override_active ? [
    "1. Fix the emergency issue",
    "2. Remove emergency_override = true from configuration",
    "3. Run terraform apply to re-enable controls",
    "4. Document all actions taken",
    "5. Schedule post-incident review"
  ] : ["No emergency override active"]
}