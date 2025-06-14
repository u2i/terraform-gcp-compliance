# ISO 27001 A.9 - Access Control (Fixed for Project Level)
resource "google_iam_deny_policy" "iso27001_access_control" {
  count = var.enabled ? 1 : 0
  
  parent       = var.project_resource
  name         = "iso27001-a9-access-control"
  display_name = "ISO 27001 A.9 - Access Control"
  
  rules {
    description = "Enforce access control requirements per ISO 27001 A.9"
    
    deny_rule {
      denied_permissions = [
        # Only permissions valid at project level with FQDNs
        "iam.googleapis.com/serviceAccounts.getAccessToken",
        "iam.googleapis.com/serviceAccounts.signBlob",
        "iam.googleapis.com/serviceAccounts.signJwt",
        "iam.googleapis.com/serviceAccountKeys.get",
        "iam.googleapis.com/serviceAccountKeys.list"
      ]
      
      # Deny unless MFA is verified
      denial_condition {
        title       = "Require MFA"
        description = "Multi-factor authentication required"
        expression  = "!request.auth.access_levels.exists(l, l == 'mfa_verified')"
      }
      
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = var.exception_principals
    }
  }
}
