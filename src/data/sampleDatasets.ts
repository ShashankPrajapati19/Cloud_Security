/**
 * Curated Demo Datasets for CloudGuard Security Auditor Demonstrations
 * Includes Realistic Enterprise FinTech, HealthTech HIPAA, and Cloud Infrastructure Scenarios.
 */

export interface DemoDatasetItem {
  id: string;
  name: string;
  fileName: string;
  type: 'json' | 'csv';
  industry: string;
  findingsCount: number;
  environment: string;
  summaryText: string;
  tags: string[];
  content: string;
}

export const DATASET_ENTERPRISE_AWS = JSON.stringify(
  {
    metadata: {
      dataset_name: "enterprise_aws_audit.json",
      description: "CloudGuard Comprehensive Audit Dataset - Enterprise Cloud Architecture with 15 Planted Flaws",
      generator: "CloudGuard Auditor Engine v1.4.2",
      timestamp: "2026-10-28T14:30:00Z",
      version: "1.4.2",
      compliance_target: ["CIS AWS Foundations Benchmark v1.4.0", "NIST SP 800-53 Rev. 5"]
    },
    environment: {
      account_id: "714305265226 (Enterprise Core)",
      account_alias: "enterprise-security-lab",
      region: "us-east-1",
      simulation_engine: "moto-aws-mock-v5",
      is_live_aws: false,
      notes: "DEMO DATA — SIMULATED, NOT A LIVE AWS SCAN. Ground-truth benchmark dataset."
    },
    summary: {
      score: 10,
      grade: "F",
      findings_count: 15,
      severity_counts: {
        CRITICAL: 3,
        HIGH: 6,
        MEDIUM: 4,
        LOW: 2
      },
      compliance: {
        cis: 0.0,
        nist: 0.0
      },
      accuracy: {
        precision: 1.0,
        recall: 1.0,
        planted: 15,
        found: 15,
        correct: 15
      }
    },
    resources: {
      s3: [
        {
          name: "corp-public-logs-bucket",
          public_acl: true,
          encrypted: false,
          pab: false,
          versioning: true
        },
        {
          name: "corp-secure-data-lake",
          public_acl: false,
          encrypted: true,
          pab: true,
          versioning: true
        },
        {
          name: "corp-backup-vault-no-versioning",
          public_acl: false,
          encrypted: true,
          pab: true,
          versioning: false
        }
      ],
      sg: [
        {
          id: "sg-01aa9901",
          group_name: "default",
          description: "default VPC security group",
          ip_permissions: []
        },
        {
          id: "sg-02bb9902",
          group_name: "bastion-open-ssh",
          description: "SSH open to internet 0.0.0.0/0",
          ip_permissions: [
            {
              protocol: "tcp",
              from_port: 22,
              to_port: 22,
              cidr: "0.0.0.0/0"
            }
          ]
        },
        {
          id: "sg-03cc9903",
          group_name: "dev-ingress-open-all",
          description: "All inbound traffic open 0.0.0.0/0",
          ip_permissions: [
            {
              protocol: "-1",
              cidr: "0.0.0.0/0"
            }
          ]
        },
        {
          id: "sg-04dd9904",
          group_name: "prod-web-https",
          description: "HTTPS only for reverse proxy",
          ip_permissions: [
            {
              protocol: "tcp",
              from_port: 443,
              to_port: 443,
              cidr: "0.0.0.0/0"
            }
          ]
        }
      ],
      volumes: [
        {
          id: "vol-0a89f31c2d449e55a",
          encrypted: false,
          size_gb: 120,
          az: "us-east-1a"
        },
        {
          id: "vol-0b77e22d91a4000f5",
          encrypted: true,
          size_gb: 250,
          az: "us-east-1a"
        }
      ],
      iam_users: [
        {
          name: "dev-admin",
          mfa: false,
          admin: true,
          key_ages: []
        },
        {
          name: "analyst-auditor",
          mfa: true,
          admin: false,
          key_ages: []
        },
        {
          name: "legacy-ci-service",
          mfa: true,
          admin: false,
          key_ages: [2479]
        }
      ],
      password_policy: {
        min_length: 6,
        require_symbols: false,
        require_numbers: false,
        require_uppercase: false,
        require_lowercase: false,
        max_age_days: 0,
        reuse_prevention: 0
      },
      rds: [
        {
          id: "corp-aurora-production",
          publicly_accessible: true,
          storage_encrypted: false,
          engine: "aurora-postgresql",
          db_class: "db.r6g.large"
        },
        {
          id: "corp-aurora-replica-safe",
          publicly_accessible: false,
          storage_encrypted: true,
          engine: "aurora-postgresql",
          db_class: "db.r6g.large"
        }
      ],
      trails: [],
      kms: [
        {
          id: "c53d1f55-a756-4c14-9a6e-e2f36b1a00e6",
          description: "CMK application tokenization key (rotation OFF)",
          rotation: false,
          manager: "CUSTOMER",
          state: "Enabled",
          key_spec: "SYMMETRIC_DEFAULT"
        },
        {
          id: "56341802-8890-4991-91fc-9b43c9ea973e",
          description: "CMK database encryption key (rotation ON)",
          rotation: true,
          manager: "CUSTOMER",
          state: "Enabled",
          key_spec: "SYMMETRIC_DEFAULT"
        }
      ]
    },
    findings: [
      {
        rule_id: "S3-001",
        severity: "CRITICAL",
        service: "S3",
        resource: "corp-public-logs-bucket",
        description: "S3 bucket is open to the public (ACL grant to AllUsers)",
        cis: "2.1.5",
        nist: "AC-3",
        remediation: "Make the ACL private and turn on S3 Block Public Access across all 4 controls."
      },
      {
        rule_id: "S3-002",
        severity: "HIGH",
        service: "S3",
        resource: "corp-public-logs-bucket",
        description: "S3 bucket has no default server-side encryption enabled",
        cis: "2.1.1",
        nist: "SC-28",
        remediation: "Turn on default encryption (SSE-S3 AES-256 or SSE-KMS CMK)."
      },
      {
        rule_id: "S3-003",
        severity: "MEDIUM",
        service: "S3",
        resource: "corp-public-logs-bucket",
        description: "S3 Block Public Access is not fully enabled at bucket level",
        cis: "2.1.5",
        nist: "AC-3",
        remediation: "Enable all four S3 Block Public Access configurations."
      },
      {
        rule_id: "S3-004",
        severity: "LOW",
        service: "S3",
        resource: "corp-backup-vault-no-versioning",
        description: "S3 bucket versioning is disabled; vulnerable to ransomware or accidental deletes",
        cis: "-",
        nist: "CP-9",
        remediation: "Enable S3 bucket versioning with optional MFA Delete."
      },
      {
        rule_id: "EC2-001",
        severity: "HIGH",
        service: "EC2",
        resource: "bastion-open-ssh",
        description: "SSH port 22 is open to the world (0.0.0.0/0)",
        cis: "5.2",
        nist: "SC-7",
        remediation: "Restrict SSH to trusted CIDR blocks (/32) or transition to AWS Systems Manager Session Manager."
      },
      {
        rule_id: "EC2-002",
        severity: "CRITICAL",
        service: "EC2",
        resource: "dev-ingress-open-all",
        description: "ALL ingress ports (-1 protocol) open to the internet (0.0.0.0/0)",
        cis: "5.2",
        nist: "SC-7",
        remediation: "Remove wildcard 0.0.0.0/0 ingress rule and scope down to specific application ports."
      },
      {
        rule_id: "EC2-003",
        severity: "MEDIUM",
        service: "EBS",
        resource: "vol-0a89f31c2d449e55a",
        description: "Attached EBS root storage volume is unencrypted",
        cis: "2.2.1",
        nist: "SC-28",
        remediation: "Take snapshot, copy snapshot with KMS encryption, and create encrypted volume replacement."
      },
      {
        rule_id: "IAM-001",
        severity: "HIGH",
        service: "IAM",
        resource: "dev-admin",
        description: "Privileged administrator user does not have Multi-Factor Authentication (MFA) enabled",
        cis: "1.10",
        nist: "IA-2(1)",
        remediation: "Enforce virtual FIDO2/WebAuthn or TOTP MFA token registration."
      },
      {
        rule_id: "IAM-002",
        severity: "CRITICAL",
        service: "IAM",
        resource: "dev-admin",
        description: "IAM user has unrestricted administrator access (*:*) via AdministratorAccess policy",
        cis: "1.16",
        nist: "AC-6",
        remediation: "Detach AdministratorAccess and attach least-privilege role with permission boundaries."
      },
      {
        rule_id: "IAM-003",
        severity: "MEDIUM",
        service: "IAM",
        resource: "legacy-ci-service",
        description: "Active IAM access key is older than 90 days (2,479 days old)",
        cis: "1.14",
        nist: "IA-5",
        remediation: "Rotate IAM access key immediately and decommission old inactive credentials."
      },
      {
        rule_id: "IAM-004",
        severity: "MEDIUM",
        service: "IAM",
        resource: "account",
        description: "Account password policy does not meet CIS AWS Benchmark complexity standards",
        cis: "1.8",
        nist: "IA-5(1)",
        remediation: "Update account password policy: min length 14, uppercase, lowercase, numbers, symbols, 90-day expiry."
      },
      {
        rule_id: "RDS-001",
        severity: "HIGH",
        service: "RDS",
        resource: "corp-aurora-production",
        description: "RDS database instance has public IP assignment and is accessible from the internet",
        cis: "2.3.3",
        nist: "SC-7",
        remediation: "Modify DB instance setting PubliclyAccessible=false and deploy inside private VPC subnets."
      },
      {
        rule_id: "RDS-002",
        severity: "HIGH",
        service: "RDS",
        resource: "corp-aurora-production",
        description: "RDS relational database storage is unencrypted at rest",
        cis: "2.3.1",
        nist: "SC-28",
        remediation: "Snapshot unencrypted instance, copy snapshot with AWS KMS CMK encryption, and restore."
      },
      {
        rule_id: "CT-001",
        severity: "HIGH",
        service: "CloudTrail",
        resource: "account",
        description: "No active multi-region CloudTrail trail found; API audit logging is disabled",
        cis: "3.1",
        nist: "AU-2",
        remediation: "Create an organization-wide multi-region CloudTrail trail logging all management and data events."
      },
      {
        rule_id: "KMS-001",
        severity: "LOW",
        service: "KMS",
        resource: "c53d1f55-a756-4c14-9a6e-e2f36b1a00e6",
        description: "Customer managed KMS master key does not have automatic yearly rotation enabled",
        cis: "3.8",
        nist: "SC-12",
        remediation: "Enable annual key rotation via aws kms enable-key-rotation."
      }
    ]
  },
  null,
  2
);

export const DATASET_FINTECH_PCI = JSON.stringify(
  {
    metadata: {
      dataset_name: "fintech_pci_dss_audit.json",
      description: "FinTech Vault Payment Infrastructure - PCI-DSS v4.0 & SOC2 Type II Cloud Security Audit",
      generator: "CloudGuard Auditor Engine v1.4.2",
      timestamp: "2026-10-28T16:00:00Z",
      version: "1.4.2",
      compliance_target: ["PCI-DSS v4.0 Req 1, 3, 7, 8, 10", "SOC2 CC6.1 - CC6.6"]
    },
    environment: {
      account_id: "482910482910 (FinTech Prod Vault)",
      account_alias: "fintech-payment-vault-prod",
      region: "us-east-2",
      simulation_engine: "moto-aws-mock-v5",
      is_live_aws: false,
      notes: "DEMO DATA — Cardholder Data Environment (CDE) Synthetic Audit File"
    },
    summary: {
      score: 18,
      grade: "F",
      findings_count: 10,
      severity_counts: {
        CRITICAL: 2,
        HIGH: 5,
        MEDIUM: 2,
        LOW: 1
      },
      compliance: {
        cis: 15.0,
        nist: 12.5
      },
      accuracy: {
        precision: 1.0,
        recall: 1.0,
        planted: 10,
        found: 10,
        correct: 10
      }
    },
    resources: {
      s3: [
        {
          name: "pci-raw-cardholder-token-vault",
          public_acl: true,
          encrypted: false,
          pab: false,
          versioning: true
        },
        {
          name: "pci-settlement-receipts-2026",
          public_acl: false,
          encrypted: true,
          pab: true,
          versioning: true
        }
      ],
      sg: [
        {
          id: "sg-pci-gw-9921",
          group_name: "payment-gateway-dmz",
          description: "PCI Ingress DMZ security group",
          ip_permissions: [
            {
              protocol: "tcp",
              from_port: 22,
              to_port: 22,
              cidr: "0.0.0.0/0"
            },
            {
              protocol: "tcp",
              from_port: 443,
              to_port: 443,
              cidr: "0.0.0.0/0"
            }
          ]
        }
      ],
      volumes: [
        {
          id: "vol-pci-core-ledger-db",
          encrypted: false,
          size_gb: 500,
          az: "us-east-2a"
        }
      ],
      iam_users: [
        {
          name: "pci-deployer-svc",
          mfa: false,
          admin: true,
          key_ages: [385]
        },
        {
          name: "settlement-officer",
          mfa: true,
          admin: false,
          key_ages: [45]
        }
      ],
      password_policy: {
        min_length: 8,
        require_symbols: false,
        require_numbers: true,
        require_uppercase: false,
        require_lowercase: true,
        max_age_days: 0,
        reuse_prevention: 0
      },
      rds: [
        {
          id: "pci-cardholder-postgres-primary",
          publicly_accessible: true,
          storage_encrypted: false,
          engine: "postgres",
          db_class: "db.m5.2xlarge"
        }
      ],
      trails: [],
      kms: [
        {
          id: "kms-pci-tokenization-master",
          description: "PCI Master Card Encryption Key",
          rotation: false,
          manager: "CUSTOMER",
          state: "Enabled",
          key_spec: "SYMMETRIC_DEFAULT"
        }
      ]
    },
    findings: [
      {
        rule_id: "S3-001",
        severity: "CRITICAL",
        service: "S3",
        resource: "pci-raw-cardholder-token-vault",
        description: "PCI token vault bucket has Public Read ACL enabled (PCI-DSS Req 1.3)",
        cis: "2.1.5",
        nist: "AC-3",
        remediation: "Remove public ACL grants and enforce S3 Block Public Access immediately."
      },
      {
        rule_id: "S3-002",
        severity: "HIGH",
        service: "S3",
        resource: "pci-raw-cardholder-token-vault",
        description: "Cardholder token storage bucket lacks default encryption at rest (PCI-DSS Req 3.4)",
        cis: "2.1.1",
        nist: "SC-28",
        remediation: "Enable SSE-KMS customer-managed key encryption."
      },
      {
        rule_id: "EC2-001",
        severity: "HIGH",
        service: "EC2",
        resource: "payment-gateway-dmz",
        description: "SSH administration port exposed directly to the public internet (PCI-DSS Req 1.2)",
        cis: "5.2",
        nist: "SC-7",
        remediation: "Close port 22 to 0.0.0.0/0 and route administrative traffic through VPN bastion."
      },
      {
        rule_id: "EC2-003",
        severity: "MEDIUM",
        service: "EBS",
        resource: "vol-pci-core-ledger-db",
        description: "Attached transaction ledger EBS volume is unencrypted",
        cis: "2.2.1",
        nist: "SC-28",
        remediation: "Encrypt volume using KMS customer master key."
      },
      {
        rule_id: "IAM-001",
        severity: "HIGH",
        service: "IAM",
        resource: "pci-deployer-svc",
        description: "High-privilege deployment account lacks multi-factor authentication (PCI-DSS Req 8.3)",
        cis: "1.10",
        nist: "IA-2(1)",
        remediation: "Enforce hardware or virtual MFA device requirement."
      },
      {
        rule_id: "IAM-002",
        severity: "CRITICAL",
        service: "IAM",
        resource: "pci-deployer-svc",
        description: "Service user possesses unrestricted AdministratorAccess (*:*) in Cardholder environment",
        cis: "1.16",
        nist: "AC-6",
        remediation: "Apply role-based access control and principle of least privilege."
      },
      {
        rule_id: "IAM-003",
        severity: "MEDIUM",
        service: "IAM",
        resource: "pci-deployer-svc",
        description: "Payment service access keys have not been rotated in 385 days (PCI-DSS Req 8.2.4)",
        cis: "1.14",
        nist: "IA-5",
        remediation: "Rotate credentials within a strict 90-day cycle."
      },
      {
        rule_id: "RDS-001",
        severity: "HIGH",
        service: "RDS",
        resource: "pci-cardholder-postgres-primary",
        description: "Cardholder database instance is publicly reachable over public internet IP",
        cis: "2.3.3",
        nist: "SC-7",
        remediation: "Disable PubliclyAccessible flag and isolate inside private database subnets."
      },
      {
        rule_id: "RDS-002",
        severity: "HIGH",
        service: "RDS",
        resource: "pci-cardholder-postgres-primary",
        description: "Primary database storage lacks encryption at rest for sensitive card records",
        cis: "2.3.1",
        nist: "SC-28",
        remediation: "Migrate database to encrypted storage volume."
      },
      {
        rule_id: "KMS-001",
        severity: "LOW",
        service: "KMS",
        resource: "kms-pci-tokenization-master",
        description: "KMS Tokenization Master Key rotation is disabled",
        cis: "3.8",
        nist: "SC-12",
        remediation: "Enable automated yearly key rotation."
      }
    ]
  },
  null,
  2
);

export const DATASET_HEALTHCARE_HIPAA = JSON.stringify(
  {
    metadata: {
      dataset_name: "healthcare_hipaa_audit.json",
      description: "Apex HealthCloud Systems - HIPAA Security Rule (45 CFR § 164.312) Cloud Security Audit",
      generator: "CloudGuard Auditor Engine v1.4.2",
      timestamp: "2026-10-28T18:15:00Z",
      version: "1.4.2",
      compliance_target: ["HIPAA Security Rule", "NIST SP 800-53 Rev. 5 SC-28, AC-3, AU-2"]
    },
    environment: {
      account_id: "928173645012 (Apex Health EHR)",
      account_alias: "apex-healthcloud-ehr-prod",
      region: "us-west-2",
      simulation_engine: "moto-aws-mock-v5",
      is_live_aws: false,
      notes: "DEMO DATA — Protected Health Information (PHI) Synthetic Audit File"
    },
    summary: {
      score: 24,
      grade: "F",
      findings_count: 8,
      severity_counts: {
        CRITICAL: 2,
        HIGH: 4,
        MEDIUM: 2,
        LOW: 0
      },
      compliance: {
        cis: 25.0,
        nist: 20.0
      },
      accuracy: {
        precision: 1.0,
        recall: 1.0,
        planted: 8,
        found: 8,
        correct: 8
      }
    },
    resources: {
      s3: [
        {
          name: "apex-ehr-patient-imaging-archive",
          public_acl: true,
          encrypted: false,
          pab: false,
          versioning: false
        },
        {
          name: "apex-audit-logs-hipaa-cold",
          public_acl: false,
          encrypted: true,
          pab: true,
          versioning: true
        }
      ],
      sg: [
        {
          id: "sg-telehealth-api-gateway",
          group_name: "telehealth-fhir-ingress",
          description: "FHIR HL7 API Security Group",
          ip_permissions: [
            {
              protocol: "-1",
              cidr: "0.0.0.0/0"
            }
          ]
        }
      ],
      volumes: [
        {
          id: "vol-dicom-mri-cache",
          encrypted: false,
          size_gb: 800,
          az: "us-west-2a"
        }
      ],
      iam_users: [
        {
          name: "telehealth-dr-admin",
          mfa: false,
          admin: true,
          key_ages: []
        }
      ],
      password_policy: {
        min_length: 6,
        require_symbols: false,
        require_numbers: false,
        require_uppercase: false,
        require_lowercase: false,
        max_age_days: 0,
        reuse_prevention: 0
      },
      rds: [
        {
          id: "apex-fhir-patient-records-db",
          publicly_accessible: true,
          storage_encrypted: false,
          engine: "aurora-mysql",
          db_class: "db.r5.xlarge"
        }
      ],
      trails: [],
      kms: [
        {
          id: "kms-phi-encryption-key-01",
          description: "HIPAA PHI Data Key",
          rotation: true,
          manager: "CUSTOMER",
          state: "Enabled",
          key_spec: "SYMMETRIC_DEFAULT"
        }
      ]
    },
    findings: [
      {
        rule_id: "S3-001",
        severity: "CRITICAL",
        service: "S3",
        resource: "apex-ehr-patient-imaging-archive",
        description: "Electronic Protected Health Information (ePHI) bucket is publicly readable via ACL (HIPAA 164.312(a)(1))",
        cis: "2.1.5",
        nist: "AC-3",
        remediation: "Immediately apply S3 Block Public Access and revoke public ACL grants."
      },
      {
        rule_id: "S3-002",
        severity: "HIGH",
        service: "S3",
        resource: "apex-ehr-patient-imaging-archive",
        description: "Patient imaging archive has no encryption at rest (HIPAA 164.312(a)(2)(iv))",
        cis: "2.1.1",
        nist: "SC-28",
        remediation: "Enable SSE-KMS encryption with customer managed key."
      },
      {
        rule_id: "S3-004",
        severity: "LOW",
        service: "S3",
        resource: "apex-ehr-patient-imaging-archive",
        description: "Bucket versioning disabled; lacks ransomware rollback protection for ePHI files",
        cis: "-",
        nist: "CP-9",
        remediation: "Enable bucket versioning with object lock."
      },
      {
        rule_id: "EC2-002",
        severity: "CRITICAL",
        service: "EC2",
        resource: "telehealth-fhir-ingress",
        description: "FHIR API gateway security group allows ALL ingress traffic from 0.0.0.0/0",
        cis: "5.2",
        nist: "SC-7",
        remediation: "Restrict traffic to TLS 443 with CloudFront / AWS WAF fronting."
      },
      {
        rule_id: "EC2-003",
        severity: "MEDIUM",
        service: "EBS",
        resource: "vol-dicom-mri-cache",
        description: "EBS storage holding DICOM MRI patient scans is unencrypted",
        cis: "2.2.1",
        nist: "SC-28",
        remediation: "Encrypt EBS volume using AWS KMS."
      },
      {
        rule_id: "IAM-001",
        severity: "HIGH",
        service: "IAM",
        resource: "telehealth-dr-admin",
        description: "Clinical administrator account lacks MFA (HIPAA 164.312(d))",
        cis: "1.10",
        nist: "IA-2(1)",
        remediation: "Enforce mandatory MFA enrollment before administrative console access."
      },
      {
        rule_id: "RDS-001",
        severity: "HIGH",
        service: "RDS",
        resource: "apex-fhir-patient-records-db",
        description: "Patient records database has a public internet endpoint (HIPAA 164.312(e)(1))",
        cis: "2.3.3",
        nist: "SC-7",
        remediation: "Disable PubliclyAccessible flag and deploy within isolated VPC subnets."
      },
      {
        rule_id: "CT-001",
        severity: "HIGH",
        service: "CloudTrail",
        resource: "account",
        description: "CloudTrail audit logging is inactive (HIPAA 164.312(b) Audit Controls)",
        cis: "3.1",
        nist: "AU-2",
        remediation: "Enable multi-region CloudTrail with CloudWatch alarms."
      }
    ]
  },
  null,
  2
);

export const DATASET_ECOMMERCE_CSV = `rule_id,severity,service,resource,description,cis,nist,remediation
S3-001,CRITICAL,S3,storefront-assets-bucket,"Storefront user profile uploads bucket has public read ACL enabled",2.1.5,AC-3,"Revoke public ACLs and enforce S3 Block Public Access"
S3-002,HIGH,S3,storefront-assets-bucket,"Storefront assets bucket has no default encryption at rest",2.1.1,SC-28,"Enable SSE-S3 or SSE-KMS default encryption"
EC2-001,HIGH,EC2,sg-bastion-ssh,"SSH port 22 open to the world 0.0.0.0/0",5.2,SC-7,"Restrict port 22 access to office VPN IP"
EC2-002,CRITICAL,EC2,sg-open-staging,"All ports open to internet 0.0.0.0/0 in staging environment",5.2,SC-7,"Remove 0.0.0.0/0 rule and whitelist ports 80/443"
EC2-003,MEDIUM,EBS,vol-session-cache-01,"EBS session cache volume unencrypted at rest",2.2.1,SC-28,"Enable EBS volume encryption with KMS"
IAM-001,HIGH,IAM,storefront-admin,"Administrative user missing multi-factor authentication",1.10,IA-2(1),"Enforce MFA on all IAM users"
IAM-002,CRITICAL,IAM,storefront-admin,"IAM user has full AdministratorAccess (*:*) policy",1.16,AC-6,"Scope down IAM permissions to minimum required"
IAM-003,MEDIUM,IAM,catalog-syncer-bot,"IAM API access keys active for 312 days without rotation",1.14,IA-5,"Rotate credentials within 90 days"
RDS-001,HIGH,RDS,ecommerce-catalog-db,"Product database instance is publicly reachable on internet",2.3.3,SC-7,"Set PubliclyAccessible to false"
RDS-002,HIGH,RDS,ecommerce-catalog-db,"Database storage is unencrypted at rest",2.3.1,SC-28,"Migrate to encrypted RDS instance"
CT-001,HIGH,CloudTrail,account,"CloudTrail audit logging is disabled",3.1,AU-2,"Enable multi-region CloudTrail with S3 log storage"
KMS-001,LOW,KMS,kms-catalog-key-01,"KMS Customer Master Key annual rotation is disabled",3.8,SC-12,"Enable yearly key rotation"`;

export const CURATED_DEMO_DATASETS: DemoDatasetItem[] = [
  {
    id: "enterprise-aws",
    name: "Enterprise Core Architecture Audit",
    fileName: "sample_audit.json",
    type: "json",
    industry: "Enterprise Cloud & FinTech",
    findingsCount: 15,
    environment: "AWS us-east-1 (Account 714305265226)",
    summaryText: "Complete 15-rule baseline covering S3 public ACLs, open SSH/all security groups, unencrypted EBS, IAM admin flaws, public RDS, and inactive CloudTrail.",
    tags: ["Full Topology", "CIS AWS v1.4", "NIST SP 800-53", "15 Flaws"],
    content: DATASET_ENTERPRISE_AWS
  },
  {
    id: "fintech-pci",
    name: "FinTech Cardholder Data Environment (PCI-DSS)",
    fileName: "fintech_pci_audit.json",
    type: "json",
    industry: "Financial Services / Banking",
    findingsCount: 10,
    environment: "AWS us-east-2 (Account 482910482910)",
    summaryText: "Cardholder data environment audit demonstrating PCI-DSS v4.0 violations: public card token bucket, unencrypted ledger volumes, exposed Postgres DB, and stale keys.",
    tags: ["PCI-DSS v4.0", "SOC2 Type II", "Token Vault", "10 Flaws"],
    content: DATASET_FINTECH_PCI
  },
  {
    id: "healthcare-hipaa",
    name: "Apex HealthCloud EHR Audit (HIPAA)",
    fileName: "healthcare_hipaa_audit.json",
    type: "json",
    industry: "Healthcare & Telehealth",
    findingsCount: 8,
    environment: "AWS us-west-2 (Account 928173645012)",
    summaryText: "HIPAA Security Rule compliance audit showing exposed electronic Protected Health Information (ePHI), unencrypted DICOM imaging storage, and unrestricted FHIR API gateways.",
    tags: ["HIPAA Security Rule", "ePHI Protection", "FHIR API", "8 Flaws"],
    content: DATASET_HEALTHCARE_HIPAA
  },
  {
    id: "ecommerce-csv",
    name: "E-Commerce Retail Findings Matrix (CSV)",
    fileName: "sample_findings.csv",
    type: "csv",
    industry: "E-Commerce & Retail",
    findingsCount: 12,
    environment: "AWS Multi-Account Retail Stack",
    summaryText: "Spreadsheet-friendly CSV findings matrix with 12 security issues, CIS controls, NIST mappings, and specific remediation advice.",
    tags: ["CSV Matrix", "Spreadsheet Ready", "Retail Storefront", "12 Flaws"],
    content: DATASET_ECOMMERCE_CSV
  }
];
