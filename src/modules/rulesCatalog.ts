import { RuleDefinition } from '../types/security';

export const RULES_CATALOG: Record<string, RuleDefinition> = {
  'S3-001': {
    id: 'S3-001',
    service: 'S3',
    severity: 'CRITICAL',
    cis: '2.1.5',
    nist: 'AC-3',
    title: 'S3 bucket is open to the public (ACL)',
    remediation: 'Make the ACL private and turn on Block Public Access',
    explanation: 'S3 buckets with public ACL grants allow arbitrary internet users to read or list sensitive files, risking massive data exfiltration.'
  },
  'S3-002': {
    id: 'S3-002',
    service: 'S3',
    severity: 'HIGH',
    cis: '2.1.1',
    nist: 'SC-28',
    title: 'S3 bucket has no default encryption',
    remediation: 'Turn on default encryption (SSE-S3 or SSE-KMS)',
    explanation: 'Unencrypted storage volumes and objects fail baseline compliance for data at rest, leaving data exposed if underlying disks are breached.'
  },
  'S3-003': {
    id: 'S3-003',
    service: 'S3',
    severity: 'MEDIUM',
    cis: '2.1.5',
    nist: 'AC-3',
    title: 'S3 Block Public Access is not fully enabled',
    remediation: 'Enable all four Block Public Access settings',
    explanation: 'Without all 4 S3 Block Public Access flags activated, subsequent ACL or policy updates can accidentally expose the bucket.'
  },
  'S3-004': {
    id: 'S3-004',
    service: 'S3',
    severity: 'LOW',
    cis: null,
    nist: 'CP-9',
    title: 'S3 versioning is turned off',
    remediation: 'Enable bucket versioning so old copies can be recovered',
    explanation: 'Versioning ensures protection against accidental overwrite, ransomware tampering, or malicious object deletion.'
  },
  'EC2-001': {
    id: 'EC2-001',
    service: 'EC2',
    severity: 'HIGH',
    cis: '5.2',
    nist: 'SC-7',
    title: 'SSH/RDP port is open to the whole internet',
    remediation: 'Allow only trusted IP ranges, or use a VPN/bastion host',
    explanation: 'Port 22 (SSH) or 3389 (RDP) open to 0.0.0.0/0 leaves systems vulnerable to continuous brute-force attacks and credential stuffing.'
  },
  'EC2-002': {
    id: 'EC2-002',
    service: 'EC2',
    severity: 'CRITICAL',
    cis: '5.2',
    nist: 'SC-7',
    title: 'ALL ports are open to the whole internet',
    remediation: 'Delete the rule and allow only the ports you really need',
    explanation: 'Permitting all protocols (-1) or ports 0-65535 to 0.0.0.0/0 completely bypasses the perimeter firewall, exposing all instance services.'
  },
  'EC2-003': {
    id: 'EC2-003',
    service: 'EBS',
    severity: 'MEDIUM',
    cis: '2.2.1',
    nist: 'SC-28',
    title: 'Disk (EBS volume) is not encrypted',
    remediation: 'Copy the disk as an encrypted volume and replace it',
    explanation: 'Unencrypted EBS volumes fail data-at-rest protection requirements and increase the risk of physical data exposure.'
  },
  'IAM-001': {
    id: 'IAM-001',
    service: 'IAM',
    severity: 'HIGH',
    cis: '1.10',
    nist: 'IA-2(1)',
    title: 'User has no MFA (second login step)',
    remediation: 'Enrol an MFA device for the user',
    explanation: 'Single-factor authentication leaves high-privilege administrative accounts susceptible to password stuffing and phishing compromises.'
  },
  'IAM-002': {
    id: 'IAM-002',
    service: 'IAM',
    severity: 'CRITICAL',
    cis: '1.16',
    nist: 'AC-6',
    title: 'User has full admin rights (*:*)',
    remediation: 'Replace with a least-privilege policy',
    explanation: 'Granting wildcards on Action and Resource violates the Principle of Least Privilege and provides catastrophic blast radius on compromise.'
  },
  'IAM-003': {
    id: 'IAM-003',
    service: 'IAM',
    severity: 'MEDIUM',
    cis: '1.14',
    nist: 'IA-5',
    title: 'Access key is older than 90 days',
    remediation: 'Create a new key, update the apps, delete the old key',
    explanation: 'Stale programmatic credentials increase the window of vulnerability if a secret key has been leaked into codebase or logs.'
  },
  'IAM-004': {
    id: 'IAM-004',
    service: 'IAM',
    severity: 'MEDIUM',
    cis: '1.8',
    nist: 'IA-5(1)',
    title: 'Weak account password policy (shorter than 14)',
    remediation: 'Require 14+ characters, mixed types, and expiry',
    explanation: 'Permitting short passwords (<14 chars) without complexity rules allows weak credentials vulnerable to dictionary attacks.'
  },
  'RDS-001': {
    id: 'RDS-001',
    service: 'RDS',
    severity: 'HIGH',
    cis: '2.3.3',
    nist: 'SC-7',
    title: 'Database is reachable from the internet',
    remediation: 'Set PubliclyAccessible to false',
    explanation: 'Relational databases hosting production tables should never have public IP routing enabled; access must be restricted to private subnets.'
  },
  'RDS-002': {
    id: 'RDS-002',
    service: 'RDS',
    severity: 'HIGH',
    cis: '2.3.1',
    nist: 'SC-28',
    title: 'Database storage is not encrypted',
    remediation: 'Restore a snapshot into an encrypted instance',
    explanation: 'Databases hold sensitive customer and transaction records and must be protected by transparent KMS or storage encryption.'
  },
  'CT-001': {
    id: 'CT-001',
    service: 'CloudTrail',
    severity: 'HIGH',
    cis: '3.1',
    nist: 'AU-2',
    title: 'No active multi-region CloudTrail (no activity log)',
    remediation: 'Create a multi-region trail and start logging',
    explanation: 'Without multi-region audit logging, forensic investigations, incident response, and tamper detection are impossible.'
  },
  'KMS-001': {
    id: 'KMS-001',
    service: 'KMS',
    severity: 'LOW',
    cis: '3.8',
    nist: 'SC-12',
    title: 'Encryption key rotation is turned off',
    remediation: 'Enable automatic yearly key rotation',
    explanation: 'Disabling annual key rotation allows cryptographic keys to be used indefinitely, increasing the exposure window if a key is compromised.'
  }
};

export const FRAMEWORKS = {
  cis: 'CIS AWS Foundations Benchmark v1.4',
  nist: 'NIST SP 800-53 Rev. 5'
};
