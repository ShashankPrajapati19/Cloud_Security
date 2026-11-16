/**
 * Core type definitions for Cloud Configuration Security Auditor
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type ServiceName = 'S3' | 'EC2' | 'EBS' | 'IAM' | 'RDS' | 'CloudTrail' | 'KMS';

export interface S3Bucket {
  name: string;
  public_acl: boolean;
  encrypted: boolean;
  pab: boolean; // Public Access Block (all 4 flags)
  versioning: boolean;
}

export interface SecurityGroupRule {
  protocol: string; // 'tcp', '-1', etc.
  from_port?: number;
  to_port?: number;
  cidr: string;
}

export interface SecurityGroup {
  id: string;
  group_name: string;
  description: string;
  ip_permissions: SecurityGroupRule[];
}

export interface EBSVolume {
  id: string;
  encrypted: boolean;
  size_gb: number;
  az: string;
}

export interface IAMUser {
  name: string;
  mfa: boolean;
  admin: boolean;
  key_ages: number[]; // age in days of active access keys
}

export interface PasswordPolicy {
  min_length: number;
  require_symbols: boolean;
  require_numbers: boolean;
  require_uppercase: boolean;
  require_lowercase: boolean;
  max_age_days: number;
  reuse_prevention: number;
}

export interface RDSInstance {
  id: string;
  publicly_accessible: boolean;
  storage_encrypted: boolean;
  engine: string;
  db_class: string;
}

export interface CloudTrail {
  name: string;
  multi_region: boolean;
  logging: boolean;
  s3_bucket: string;
}

export interface KMSKey {
  id: string;
  description: string;
  rotation: boolean;
  manager: 'CUSTOMER' | 'AWS';
  state: 'Enabled' | 'Disabled';
  key_spec: string;
}

export interface CloudSnapshot {
  s3: S3Bucket[];
  sg: SecurityGroup[];
  volumes: EBSVolume[];
  iam_users: IAMUser[];
  password_policy: PasswordPolicy | null;
  rds: RDSInstance[];
  trails: CloudTrail[];
  kms: KMSKey[];
}

export interface RuleDefinition {
  id: string;
  service: ServiceName;
  severity: Severity;
  cis: string | null;
  nist: string;
  title: string;
  remediation: string;
  explanation: string;
}

export interface Finding {
  rule_id: string;
  severity: Severity;
  service: ServiceName;
  resource: string;
  description: string;
  remediation: string;
  cis: string;
  nist: string;
}

export interface ControlRow {
  control: string;
  rules: string[];
  status: 'PASS' | 'FAIL';
  failing_resources: number;
  framework: 'cis' | 'nist';
  title?: string;
}

export interface ComplianceSummary {
  cis: number;
  nist: number;
}

export interface GroundTruthItem {
  resource: string;
  rule_id: string;
}

export interface AccuracyEvaluation {
  planted: number;
  found: number;
  correct: number;
  precision: number;
  recall: number;
  missed: GroundTruthItem[];
  false_alarms: GroundTruthItem[];
}

export interface RemediationAction {
  rule_id: string;
  resource: string;
  status: 'FIXED' | 'MANUAL' | 'ERROR';
  what_was_done: string;
}

export interface EncryptedSummaryPayload {
  algorithm: string;
  kdf: string;
  iterations: number;
  saltHex: string;
  ivHex: string;
  ciphertextBase64: string;
  sha256PlaintextHash: string;
  createdAt: string;
  summarySnapshot: {
    title: string;
    score: number;
    grade: string;
    findingsCount: number;
    cisPercent: number;
    nistPercent: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
}

export interface DemoAuditEnvironment {
  account_id?: string;
  region?: string;
  simulation_engine?: string;
  is_live_aws?: boolean;
  notes?: string;
}

export interface DemoAuditMetadata {
  dataset_name?: string;
  description?: string;
  generator?: string;
  timestamp?: string;
  version?: string;
}

export interface DemoAuditSummary {
  score?: number;
  grade?: string;
  findings_count?: number;
  severity_counts?: {
    CRITICAL?: number;
    HIGH?: number;
    MEDIUM?: number;
    LOW?: number;
  };
  compliance?: {
    cis?: number;
    nist?: number;
  };
  accuracy?: {
    precision?: number;
    recall?: number;
    planted?: number;
    found?: number;
    correct?: number;
  };
}

export interface ImportedAuditDataset {
  sourceType: 'json' | 'csv';
  fileName: string;
  importedAt: string;
  isDemoDataset: boolean;
  hasResources: boolean;
  environment?: DemoAuditEnvironment;
  metadata?: DemoAuditMetadata;
  rawSummary?: DemoAuditSummary;
  resources?: CloudSnapshot;
  findings: Finding[];
}
