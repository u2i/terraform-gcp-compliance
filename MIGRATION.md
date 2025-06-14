# Migration Guide

## From ISO 27001 Module to Comprehensive Compliance Module

### Why Migrate?

The new compliance module offers:
- **Multi-framework support**: ISO 27001, SOC 2, PCI DSS, HIPAA, GDPR
- **Unified controls**: Shared controls reduce duplication
- **Better customization**: Fine-grained control over each framework
- **Compliance reporting**: Built-in dashboards and evidence collection
- **Future-proof**: Easy to add new frameworks

### Migration Steps

#### 1. Update Module Source

**Before:**
```hcl
module "iso27001_compliance" {
  source = "github.com/u2i/terraform-iso27001-module//modules/project-compliance?ref=v1.0.0"
  # ...
}
```

**After:**
```hcl
module "compliance" {
  source = "github.com/u2i/terraform-gcp-compliance//modules/project?ref=v1.0.0"
  
  # Enable ISO 27001 to maintain existing controls
  enable_iso27001 = true
  # ... other configuration
}
```

#### 2. Map Variables

| Old Variable | New Variable | Notes |
|--------------|--------------|-------|
| `enable_resource_protection` | Automatic based on framework | Always enabled for ISO 27001 |
| `enable_iam_protection` | Automatic based on framework | Always enabled for ISO 27001 |
| `enable_audit_protection` | `security_controls.audit_logging` | More options available |
| `enable_data_protection` | `security_controls.data_protection` | Enhanced controls |
| `enable_network_protection` | `security_controls.network_security` | More granular |
| `allowed_regions` | `data_residency.regions` | Now includes enabled flag |
| `audit_logs_bucket` | `evidence_storage.bucket_name` | Expanded to evidence storage |

#### 3. State Migration

The module creates different resource names. To preserve existing deny policies:

```bash
# List existing resources
terraform state list | grep google_iam_deny_policy

# Move each resource to new name
terraform state mv \
  module.iso27001_compliance.google_iam_deny_policy.prevent_resource_deletion[0] \
  module.compliance.module.iso27001_controls[0].google_iam_deny_policy.resource_protection[0]
```

#### 4. Add New Frameworks

Once migrated, easily add new frameworks:

```hcl
module "compliance" {
  source = "github.com/u2i/terraform-gcp-compliance//modules/project?ref=v1.0.0"
  
  # Existing
  enable_iso27001 = true
  
  # Add new frameworks
  enable_soc2 = true
  compliance_frameworks = {
    soc2 = {
      enabled        = true
      trust_criteria = ["security", "availability"]
    }
  }
}
```

### Rollback Plan

If issues arise:

1. **Keep the old module version** in your requirements
2. **Comment out new module** and uncomment old module
3. **Run terraform plan** to verify no destructive changes
4. **Report issues** via GitHub Issues

### Breaking Changes

- Resource names have changed (use state mv)
- Some variables renamed (see mapping table)
- Output structure is different
- Minimum Terraform version is now 1.0 (was 0.15)

### Getting Help

- **Documentation**: See README.md for full documentation
- **Examples**: Check examples/ directory
- **Support**: File issues in GitHub
- **Slack**: #gcp-compliance channel

### Timeline

1. **Phase 1** (Current): Both modules available
2. **Phase 2** (3 months): ISO 27001-only module deprecated
3. **Phase 3** (6 months): ISO 27001-only module archived

Plan your migration within the next 3 months to ensure continued support.