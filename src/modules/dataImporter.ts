import {
  CloudSnapshot,
  Finding,
  ImportedAuditDataset,
  Severity,
  ServiceName
} from '../types/security';
import { RULES_CATALOG } from './rulesCatalog';

const VALID_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const VALID_SERVICES: ServiceName[] = ['S3', 'EC2', 'EBS', 'IAM', 'RDS', 'CloudTrail', 'KMS'];

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  dataset?: ImportedAuditDataset;
}

/**
 * Robust CSV Line Parser that handles escaped quotes and internal commas
 */
function parseCsvLine(text: string): string[] {
  const result: string[] = [];
  let cur = '';
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const nextChar = text[i + 1];

    if (char === '"') {
      if (inQuotes && nextChar === '"') {
        cur += '"';
        i++; // skip next quote
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      result.push(cur.trim());
      cur = '';
    } else {
      cur += char;
    }
  }
  result.push(cur.trim());
  return result;
}

/**
 * Validate and parse CSV content (e.g., sample_findings.csv)
 */
export function parseAndValidateCsv(content: string, fileName: string): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!content || !content.trim()) {
    return {
      isValid: false,
      errors: ['File is empty. Please upload a valid CSV file with findings.'],
      warnings
    };
  }

  const rawLines = content.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (rawLines.length < 2) {
    return {
      isValid: false,
      errors: ['CSV file must contain a header row and at least one finding row.'],
      warnings
    };
  }

  const headerTokens = parseCsvLine(rawLines[0]).map((h) => h.toLowerCase().replace(/[\s_-]/g, ''));

  // Required column detection
  const colIndex = {
    rule_id: headerTokens.findIndex((h) => ['ruleid', 'rule', 'id'].includes(h)),
    severity: headerTokens.findIndex((h) => ['severity', 'level', 'sev'].includes(h)),
    service: headerTokens.findIndex((h) => ['service', 'cloudservice', 'type'].includes(h)),
    resource: headerTokens.findIndex((h) => ['resource', 'target', 'affectedresource', 'asset'].includes(h)),
    description: headerTokens.findIndex((h) => ['description', 'issue', 'title', 'summary'].includes(h)),
    remediation: headerTokens.findIndex((h) => ['remediation', 'fix', 'guidance', 'recommendation'].includes(h)),
    cis: headerTokens.findIndex((h) => ['cis', 'ciscontrol', 'cisbenchmark'].includes(h)),
    nist: headerTokens.findIndex((h) => ['nist', 'nistcontrol'].includes(h))
  };

  if (colIndex.rule_id === -1) errors.push("Missing required column 'rule_id' (or 'rule') in CSV header.");
  if (colIndex.severity === -1) errors.push("Missing required column 'severity' in CSV header.");
  if (colIndex.resource === -1) errors.push("Missing required column 'resource' in CSV header.");

  if (errors.length > 0) {
    return { isValid: false, errors, warnings };
  }

  const findings: Finding[] = [];

  for (let i = 1; i < rawLines.length; i++) {
    const lineNum = i + 1;
    const tokens = parseCsvLine(rawLines[i]);

    if (tokens.length <= 1 && !tokens[0]) continue; // skip blank row

    const ruleId = (tokens[colIndex.rule_id] || '').trim().toUpperCase();
    const rawSev = (tokens[colIndex.severity] || '').trim().toUpperCase();
    const resource = (tokens[colIndex.resource] || '').trim();

    if (!ruleId) {
      errors.push(`Row ${lineNum}: Missing 'rule_id'.`);
      continue;
    }

    if (!VALID_SEVERITIES.includes(rawSev as Severity)) {
      errors.push(`Row ${lineNum}: Invalid severity '${rawSev}'. Must be CRITICAL, HIGH, MEDIUM, or LOW.`);
      continue;
    }

    if (!resource) {
      errors.push(`Row ${lineNum}: Missing 'resource' name.`);
      continue;
    }

    // Lookup known rule defaults if catalog matches
    const knownRule = RULES_CATALOG[ruleId];

    const service = (
      colIndex.service !== -1 && tokens[colIndex.service]
        ? tokens[colIndex.service].trim()
        : knownRule?.service || 'EC2'
    ) as ServiceName;

    const description =
      colIndex.description !== -1 && tokens[colIndex.description]
        ? tokens[colIndex.description].trim()
        : knownRule?.title || `Security configuration violation (${ruleId})`;

    const remediation =
      colIndex.remediation !== -1 && tokens[colIndex.remediation]
        ? tokens[colIndex.remediation].trim()
        : knownRule?.remediation || 'Remediate cloud resource configuration to meet security standards.';

    const cis =
      colIndex.cis !== -1 && tokens[colIndex.cis]
        ? tokens[colIndex.cis].trim()
        : knownRule?.cis || '-';

    const nist =
      colIndex.nist !== -1 && tokens[colIndex.nist]
        ? tokens[colIndex.nist].trim()
        : knownRule?.nist || 'SC-7';

    findings.push({
      rule_id: ruleId,
      severity: rawSev as Severity,
      service: VALID_SERVICES.includes(service) ? service : 'EC2',
      resource,
      description,
      remediation,
      cis,
      nist
    });
  }

  if (findings.length === 0 && errors.length === 0) {
    errors.push('No valid finding rows were found in the CSV.');
  }

  if (errors.length > 0) {
    return { isValid: false, errors, warnings };
  }

  warnings.push('CSV contains findings only. Simulated cloud resource topology is not included in CSV exports.');

  const dataset: ImportedAuditDataset = {
    sourceType: 'csv',
    fileName,
    importedAt: new Date().toISOString(),
    isDemoDataset: true,
    hasResources: false,
    findings,
    metadata: {
      dataset_name: fileName,
      description: 'Imported security findings matrix from CSV file',
      timestamp: new Date().toISOString()
    },
    environment: {
      simulation_engine: 'Synthetic CSV Demonstration Dataset',
      is_live_aws: false,
      notes: 'Demo findings imported from local file. No live AWS resources queried.'
    }
  };

  return {
    isValid: true,
    errors: [],
    warnings,
    dataset
  };
}

/**
 * Validate and parse JSON content (e.g., sample_audit.json)
 */
export function parseAndValidateJson(content: string, fileName: string): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!content || !content.trim()) {
    return {
      isValid: false,
      errors: ['File is empty. Please upload a valid JSON file.'],
      warnings
    };
  }

  let parsed: any;
  try {
    parsed = JSON.parse(content);
  } catch (err: any) {
    return {
      isValid: false,
      errors: [`Invalid JSON syntax: ${err.message || 'Unable to parse JSON document'}`],
      warnings
    };
  }

  if (!parsed || typeof parsed !== 'object') {
    return {
      isValid: false,
      errors: ['Invalid JSON format: Expected a JSON object or array of findings.'],
      warnings
    };
  }

  // Handle case where JSON is an array of findings
  const rawFindings = Array.isArray(parsed) ? parsed : parsed.findings;
  const rawResources = parsed.resources;

  if (!rawFindings && !rawResources) {
    return {
      isValid: false,
      errors: [
        "The uploaded JSON file does not contain expected audit data. Expected at least 'findings' array or 'resources' object."
      ],
      warnings
    };
  }

  // Validate and normalize findings if present
  const findings: Finding[] = [];
  if (Array.isArray(rawFindings)) {
    rawFindings.forEach((item: any, index: number) => {
      const rowNum = index + 1;
      if (!item || typeof item !== 'object') {
        errors.push(`Finding #${rowNum}: Expected an object.`);
        return;
      }

      const ruleId = String(item.rule_id || item.rule || '').trim().toUpperCase();
      const rawSev = String(item.severity || item.level || '').trim().toUpperCase();
      const resource = String(item.resource || item.target || '').trim();

      if (!ruleId) {
        errors.push(`Finding #${rowNum}: Missing 'rule_id'.`);
        return;
      }

      if (!VALID_SEVERITIES.includes(rawSev as Severity)) {
        errors.push(`Finding #${rowNum}: Invalid severity '${rawSev}'. Must be CRITICAL, HIGH, MEDIUM, or LOW.`);
        return;
      }

      if (!resource) {
        errors.push(`Finding #${rowNum}: Missing 'resource'.`);
        return;
      }

      const knownRule = RULES_CATALOG[ruleId];
      const service = (item.service || knownRule?.service || 'EC2') as ServiceName;

      findings.push({
        rule_id: ruleId,
        severity: rawSev as Severity,
        service: VALID_SERVICES.includes(service) ? service : 'EC2',
        resource,
        description: String(item.description || item.issue || knownRule?.title || `Issue ${ruleId}`),
        remediation: String(item.remediation || item.fix || knownRule?.remediation || 'Remediate resource.'),
        cis: String(item.cis || knownRule?.cis || '-'),
        nist: String(item.nist || knownRule?.nist || 'SC-7')
      });
    });
  }

  // Normalize resources if present
  let normalizedResources: CloudSnapshot | undefined = undefined;
  if (rawResources && typeof rawResources === 'object') {
    normalizedResources = {
      s3: Array.isArray(rawResources.s3)
        ? rawResources.s3.map((b: any) => ({
            name: String(b.name || 'unnamed-bucket'),
            public_acl: Boolean(b.public_acl),
            encrypted: Boolean(b.encrypted),
            pab: Boolean(b.pab),
            versioning: Boolean(b.versioning)
          }))
        : [],
      sg: Array.isArray(rawResources.sg || rawResources.security_groups)
        ? (rawResources.sg || rawResources.security_groups).map((sg: any) => ({
            id: String(sg.id || 'sg-demo'),
            group_name: String(sg.group_name || sg.name || 'unnamed-sg'),
            description: String(sg.description || 'Imported security group'),
            ip_permissions: Array.isArray(sg.ip_permissions)
              ? sg.ip_permissions.map((p: any) => ({
                  protocol: String(p.protocol || 'tcp'),
                  from_port: p.from_port !== undefined ? Number(p.from_port) : undefined,
                  to_port: p.to_port !== undefined ? Number(p.to_port) : undefined,
                  cidr: String(p.cidr || p.cidr_ip || '0.0.0.0/0')
                }))
              : []
          }))
        : [],
      volumes: Array.isArray(rawResources.volumes || rawResources.ebs_volumes)
        ? (rawResources.volumes || rawResources.ebs_volumes).map((v: any) => ({
            id: String(v.id || 'vol-demo'),
            encrypted: Boolean(v.encrypted),
            size_gb: Number(v.size_gb || v.size || 8),
            az: String(v.az || v.availability_zone || 'us-east-1a')
          }))
        : [],
      iam_users: Array.isArray(rawResources.iam_users || rawResources.users)
        ? (rawResources.iam_users || rawResources.users).map((u: any) => ({
            name: String(u.name || u.user_name || 'unnamed-user'),
            mfa: Boolean(u.mfa),
            admin: Boolean(u.admin),
            key_ages: Array.isArray(u.key_ages) ? u.key_ages.map(Number) : []
          }))
        : [],
      password_policy: rawResources.password_policy
        ? {
            min_length: Number(rawResources.password_policy.min_length || 6),
            require_symbols: Boolean(rawResources.password_policy.require_symbols),
            require_numbers: Boolean(rawResources.password_policy.require_numbers),
            require_uppercase: Boolean(rawResources.password_policy.require_uppercase),
            require_lowercase: Boolean(rawResources.password_policy.require_lowercase),
            max_age_days: Number(rawResources.password_policy.max_age_days || 0),
            reuse_prevention: Number(rawResources.password_policy.reuse_prevention || 0)
          }
        : null,
      rds: Array.isArray(rawResources.rds || rawResources.db_instances)
        ? (rawResources.rds || rawResources.db_instances).map((d: any) => ({
            id: String(d.id || d.db_instance_identifier || 'db-demo'),
            publicly_accessible: Boolean(d.publicly_accessible),
            storage_encrypted: Boolean(d.storage_encrypted),
            engine: String(d.engine || 'mysql'),
            db_class: String(d.db_class || d.db_instance_class || 'db.t3.micro')
          }))
        : [],
      trails: Array.isArray(rawResources.trails || rawResources.cloudtrail)
        ? (rawResources.trails || rawResources.cloudtrail).map((t: any) => ({
            name: String(t.name || 'org-trail'),
            multi_region: Boolean(t.multi_region || t.is_multi_region_trail),
            logging: Boolean(t.logging || t.is_logging),
            s3_bucket: String(t.s3_bucket || t.s3_bucket_name || 'audit-logs')
          }))
        : [],
      kms: Array.isArray(rawResources.kms || rawResources.kms_keys)
        ? (rawResources.kms || rawResources.kms_keys).map((k: any) => ({
            id: String(k.id || k.key_id || 'key-demo'),
            description: String(k.description || 'Imported KMS key'),
            rotation: Boolean(k.rotation || k.rotation_enabled),
            manager: (k.manager || 'CUSTOMER') === 'AWS' ? 'AWS' : 'CUSTOMER',
            state: (k.state || 'Enabled') as 'Enabled' | 'Disabled',
            key_spec: String(k.key_spec || 'SYMMETRIC_DEFAULT')
          }))
        : []
    };
  }

  if (errors.length > 0) {
    return { isValid: false, errors, warnings };
  }

  const dataset: ImportedAuditDataset = {
    sourceType: 'json',
    fileName,
    importedAt: new Date().toISOString(),
    isDemoDataset: true,
    hasResources: !!normalizedResources,
    findings,
    resources: normalizedResources,
    environment: parsed.environment || {
      account_id: '123456789012 (simulated)',
      region: 'us-east-1',
      simulation_engine: 'moto-aws-mock',
      is_live_aws: false
    },
    metadata: parsed.metadata || {
      dataset_name: fileName,
      description: 'Simulated cloud security audit dataset',
      timestamp: new Date().toISOString()
    },
    rawSummary: parsed.summary
  };

  return {
    isValid: true,
    errors: [],
    warnings,
    dataset
  };
}

/**
 * Built-in Sample Demo JSON Content (sample_audit.json)
 */
export const SAMPLE_AUDIT_JSON_STRING = JSON.stringify(
  {
    metadata: {
      dataset_name: "sample_audit.json",
      description: "Cloud Configuration Security Auditor Synthetic Demo Dataset (15 Planted Vulnerabilities)",
      generator: "CloudGuard Auditor Engine v1.4",
      timestamp: "2026-10-15T02:00:00Z",
      version: "1.4.0"
    },
    environment: {
      account_id: "714305265226 (simulated-demo)",
      region: "us-east-1",
      simulation_engine: "moto-aws-mock-v5",
      is_live_aws: false,
      notes: "DEMO DATA — SIMULATED, NOT A LIVE AWS SCAN. Generated for compliance demonstration."
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
          name: "public-logs-bucket",
          public_acl: true,
          encrypted: false,
          pab: false,
          versioning: true
        },
        {
          name: "secure-data-bucket",
          public_acl: false,
          encrypted: true,
          pab: true,
          versioning: true
        },
        {
          name: "backup-bucket-no-versioning",
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
          group_name: "open-ssh",
          description: "SSH open to world",
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
          group_name: "open-all",
          description: "All ports open",
          ip_permissions: [
            {
              protocol: "-1",
              cidr: "0.0.0.0/0"
            }
          ]
        },
        {
          id: "sg-04dd9904",
          group_name: "web-sg",
          description: "HTTPS only",
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
          id: "vol-4d38b140cfa399e55",
          encrypted: false,
          size_gb: 8,
          az: "us-east-1a"
        },
        {
          id: "vol-7b11f15f62b4000f5",
          encrypted: true,
          size_gb: 8,
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
          name: "analyst-user",
          mfa: true,
          admin: false,
          key_ages: []
        },
        {
          name: "old-key-user",
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
          id: "prod-db",
          publicly_accessible: true,
          storage_encrypted: false,
          engine: "mysql",
          db_class: "db.t3.micro"
        },
        {
          id: "secure-db",
          publicly_accessible: false,
          storage_encrypted: true,
          engine: "mysql",
          db_class: "db.t3.micro"
        }
      ],
      trails: [],
      kms: [
        {
          id: "c53d1f55-a756-4c14-9a6e-e2f36b1a00e6",
          description: "rotation OFF",
          rotation: false,
          manager: "CUSTOMER",
          state: "Enabled",
          key_spec: "SYMMETRIC_DEFAULT"
        },
        {
          id: "56341802-8890-4991-91fc-9b43c9ea973e",
          description: "rotation ON",
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
        resource: "public-logs-bucket",
        description: "S3 bucket is open to the public (ACL)",
        cis: "2.1.5",
        nist: "AC-3",
        remediation: "Make the ACL private and turn on Block Public Access"
      },
      {
        rule_id: "S3-002",
        severity: "HIGH",
        service: "S3",
        resource: "public-logs-bucket",
        description: "S3 bucket has no default encryption",
        cis: "2.1.1",
        nist: "SC-28",
        remediation: "Turn on default encryption (SSE-S3 or SSE-KMS)"
      },
      {
        rule_id: "S3-003",
        severity: "MEDIUM",
        service: "S3",
        resource: "public-logs-bucket",
        description: "S3 Block Public Access is not fully enabled",
        cis: "2.1.5",
        nist: "AC-3",
        remediation: "Enable all four Block Public Access settings"
      },
      {
        rule_id: "S3-004",
        severity: "LOW",
        service: "S3",
        resource: "backup-bucket-no-versioning",
        description: "S3 versioning is turned off",
        cis: "-",
        nist: "CP-9",
        remediation: "Enable bucket versioning so old copies can be recovered"
      },
      {
        rule_id: "EC2-001",
        severity: "HIGH",
        service: "EC2",
        resource: "open-ssh",
        description: "SSH/RDP port is open to the whole internet",
        cis: "5.2",
        nist: "SC-7",
        remediation: "Allow only trusted IP ranges, or use a VPN/bastion host"
      },
      {
        rule_id: "EC2-002",
        severity: "CRITICAL",
        service: "EC2",
        resource: "open-all",
        description: "ALL ports are open to the whole internet",
        cis: "5.2",
        nist: "SC-7",
        remediation: "Delete the rule and allow only the ports you really need"
      },
      {
        rule_id: "EC2-003",
        severity: "MEDIUM",
        service: "EBS",
        resource: "vol-4d38b140cfa399e55",
        description: "Disk (EBS volume) is not encrypted",
        cis: "2.2.1",
        nist: "SC-28",
        remediation: "Copy the disk as an encrypted volume and replace it"
      },
      {
        rule_id: "IAM-001",
        severity: "HIGH",
        service: "IAM",
        resource: "dev-admin",
        description: "User has no MFA (second login step)",
        cis: "1.10",
        nist: "IA-2(1)",
        remediation: "Enrol an MFA device for the user"
      },
      {
        rule_id: "IAM-002",
        severity: "CRITICAL",
        service: "IAM",
        resource: "dev-admin",
        description: "User has full admin rights (*:*)",
        cis: "1.16",
        nist: "AC-6",
        remediation: "Replace with a least-privilege policy"
      },
      {
        rule_id: "IAM-003",
        severity: "MEDIUM",
        service: "IAM",
        resource: "old-key-user",
        description: "Access key is older than 90 days",
        cis: "1.14",
        nist: "IA-5",
        remediation: "Create a new key, update the apps, delete the old key"
      },
      {
        rule_id: "IAM-004",
        severity: "MEDIUM",
        service: "IAM",
        resource: "account",
        description: "Weak account password policy (shorter than 14)",
        cis: "1.8",
        nist: "IA-5(1)",
        remediation: "Require 14+ characters, mixed types, and expiry"
      },
      {
        rule_id: "RDS-001",
        severity: "HIGH",
        service: "RDS",
        resource: "prod-db",
        description: "Database is reachable from the internet",
        cis: "2.3.3",
        nist: "SC-7",
        remediation: "Set PubliclyAccessible to false"
      },
      {
        rule_id: "RDS-002",
        severity: "HIGH",
        service: "RDS",
        resource: "prod-db",
        description: "Database storage is not encrypted",
        cis: "2.3.1",
        nist: "SC-28",
        remediation: "Restore a snapshot into an encrypted instance"
      },
      {
        rule_id: "CT-001",
        severity: "HIGH",
        service: "CloudTrail",
        resource: "account",
        description: "No active multi-region CloudTrail (no activity log)",
        cis: "3.1",
        nist: "AU-2",
        remediation: "Create a multi-region trail and start logging"
      },
      {
        rule_id: "KMS-001",
        severity: "LOW",
        service: "KMS",
        resource: "c53d1f55-a756-4c14-9a6e-e2f36b1a00e6",
        description: "Encryption key rotation is turned off",
        cis: "3.8",
        nist: "SC-12",
        remediation: "Enable automatic yearly key rotation"
      }
    ]
  },
  null,
  2
);

/**
 * Built-in Sample Demo CSV Content (sample_findings.csv)
 */
export const SAMPLE_FINDINGS_CSV_STRING = `rule_id,severity,service,resource,description,cis,nist,remediation
S3-001,CRITICAL,S3,public-logs-bucket,"S3 bucket is open to the public (ACL)",2.1.5,AC-3,"Make the ACL private and turn on Block Public Access"
S3-002,HIGH,S3,public-logs-bucket,"S3 bucket has no default encryption",2.1.1,SC-28,"Turn on default encryption (SSE-S3 or SSE-KMS)"
S3-003,MEDIUM,S3,public-logs-bucket,"S3 Block Public Access is not fully enabled",2.1.5,AC-3,"Enable all four Block Public Access settings"
S3-004,LOW,S3,backup-bucket-no-versioning,"S3 versioning is turned off",-,CP-9,"Enable bucket versioning so old copies can be recovered"
EC2-001,HIGH,EC2,open-ssh,"SSH/RDP port is open to the whole internet",5.2,SC-7,"Allow only trusted IP ranges, or use a VPN/bastion host"
EC2-002,CRITICAL,EC2,open-all,"ALL ports are open to the whole internet",5.2,SC-7,"Delete the rule and allow only the ports you really need"
EC2-003,MEDIUM,EBS,vol-4d38b140cfa399e55,"Disk (EBS volume) is not encrypted",2.2.1,SC-28,"Copy the disk as an encrypted volume and replace it"
IAM-001,HIGH,IAM,dev-admin,"User has no MFA (second login step)",1.10,IA-2(1),"Enrol an MFA device for the user"
IAM-002,CRITICAL,IAM,dev-admin,"User has full admin rights (*:*)",1.16,AC-6,"Replace with a least-privilege policy"
IAM-003,MEDIUM,IAM,old-key-user,"Access key is older than 90 days",1.14,IA-5,"Create a new key, update the apps, delete the old key"
IAM-004,MEDIUM,IAM,account,"Weak account password policy (shorter than 14)",1.8,IA-5(1),"Require 14+ characters, mixed types, and expiry"
RDS-001,HIGH,RDS,prod-db,"Database is reachable from the internet",2.3.3,SC-7,"Set PubliclyAccessible to false"
RDS-002,HIGH,RDS,prod-db,"Database storage is not encrypted",2.3.1,SC-28,"Restore a snapshot into an encrypted instance"
CT-001,HIGH,CloudTrail,account,"No active multi-region CloudTrail (no activity log)",3.1,AU-2,"Create a multi-region trail and start logging"
KMS-001,LOW,KMS,c53d1f55-a756-4c14-9a6e-e2f36b1a00e6,"Encryption key rotation is turned off",3.8,SC-12,"Enable automatic yearly key rotation"`;
