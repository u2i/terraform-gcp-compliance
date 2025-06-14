# Terraform GCP Compliance Module

Comprehensive Google Cloud Platform compliance module implementing security controls for multiple compliance frameworks including ISO 27001, SOC 2 Type II, PCI DSS, HIPAA, and GDPR.

## 🎯 Supported Compliance Frameworks

- **ISO 27001:2022** - Information Security Management
- **SOC 2 Type II** - Trust Services Criteria (Security, Availability, Confidentiality)
- **PCI DSS v4.0** - Payment Card Industry Data Security Standard
- **HIPAA** - Health Insurance Portability and Accountability Act
- **GDPR** - General Data Protection Regulation

## 📋 Features

- **Multi-Framework Support**: Single module addresses multiple compliance requirements
- **Layered Security**: Organization, folder, and project-level controls
- **Flexible Configuration**: Enable only the frameworks you need
- **Audit Trail**: Comprehensive logging and monitoring
- **Break-Glass Access**: Emergency access procedures that maintain compliance
- **Automated Validation**: Scripts to verify compliance status

## 🚀 Quick Start

### Basic Implementation

```hcl
module "compliance" {
  source  = "github.com/u2i/terraform-gcp-compliance//modules/project"
  version = "~> 1.0"
  
  project_id        = var.project_id
  break_glass_group = data.terraform_remote_state.org.outputs.break_glass_group
  
  # Enable frameworks as needed
  enable_iso27001 = true
  enable_soc2     = true
  enable_pci_dss  = false
  enable_hipaa    = false
  enable_gdpr     = false
}
```

### Advanced Implementation

```hcl
module "compliance" {
  source  = "github.com/u2i/terraform-gcp-compliance//modules/project"
  version = "~> 1.0"
  
  project_id        = var.project_id
  break_glass_group = var.break_glass_group
  
  # Framework selection
  compliance_frameworks = {
    iso27001 = {
      enabled = true
      level   = "high"  # high, medium, low
    }
    soc2 = {
      enabled      = true
      trust_criteria = ["security", "availability", "confidentiality"]
    }
    pci_dss = {
      enabled = true
      level   = 1  # 1-4 based on transaction volume
    }
  }
  
  # Data classification
  data_classification = "confidential"  # public, internal, confidential, restricted
  
  # Regional restrictions
  data_residency = {
    enabled = true
    regions = ["us-central1", "us-east1"]
  }
}
```

## 📁 Module Structure

```
modules/
├── organization/    # Organization-level compliance controls
├── folder/         # Folder-level compliance controls
├── project/        # Project-level compliance controls
├── frameworks/     # Framework-specific controls
│   ├── iso27001/
│   ├── soc2/
│   ├── pci_dss/
│   ├── hipaa/
│   └── gdpr/
└── shared/         # Shared controls across frameworks
    ├── access-control/
    ├── data-protection/
    ├── audit-logging/
    ├── encryption/
    └── network-security/
```

## 🛡️ Security Controls

### Access Control
- Multi-factor authentication enforcement
- Privileged access management
- Segregation of duties
- Regular access reviews

### Data Protection
- Encryption at rest and in transit
- Data Loss Prevention (DLP)
- Data residency controls
- Secure data disposal

### Audit & Monitoring
- Comprehensive audit logging
- Real-time security monitoring
- Incident detection and response
- Compliance reporting

### Network Security
- Network segmentation
- Firewall rules management
- DDoS protection
- SSL/TLS enforcement

## 📊 Compliance Mapping

| Control | ISO 27001 | SOC 2 | PCI DSS | HIPAA | GDPR |
|---------|-----------|--------|---------|--------|------|
| Access Control | A.9 | CC6.1 | 7, 8 | §164.312(a) | Art. 32 |
| Encryption | A.10 | CC6.7 | 3.4 | §164.312(e) | Art. 32 |
| Audit Logging | A.12.4 | CC7.2 | 10 | §164.312(b) | Art. 30 |
| Incident Response | A.16 | CC7.3 | 12 | §164.308(a)(6) | Art. 33-34 |
| Data Protection | A.8 | C1.2 | 3 | §164.312(c) | Art. 25, 32 |

## 🔧 Requirements

- Terraform >= 1.0
- Google Cloud Provider >= 5.29.0
- Organization-level permissions for initial setup
- Break-glass group configured at organization level

## 📚 Documentation

- [Implementation Guide](docs/IMPLEMENTATION.md)
- [Compliance Mapping](docs/COMPLIANCE_MAPPING.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Emergency Procedures](docs/EMERGENCY_PROCEDURES.md)

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## 📄 License

Copyright © 2024 U2I. All rights reserved.

This module is proprietary and confidential. See [LICENSE](LICENSE) for details.