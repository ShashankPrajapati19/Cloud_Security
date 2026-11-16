import { CloudSnapshot, GroundTruthItem } from '../types/security';

export const GROUND_TRUTH: GroundTruthItem[] = [
  { resource: 'public-logs-bucket', rule_id: 'S3-001' },
  { resource: 'public-logs-bucket', rule_id: 'S3-002' },
  { resource: 'public-logs-bucket', rule_id: 'S3-003' },
  { resource: 'backup-bucket-no-versioning', rule_id: 'S3-004' },
  { resource: 'open-ssh', rule_id: 'EC2-001' },
  { resource: 'open-all', rule_id: 'EC2-002' },
  { resource: 'vol-4d38b140cfa399e55', rule_id: 'EC2-003' },
  { resource: 'dev-admin', rule_id: 'IAM-001' },
  { resource: 'dev-admin', rule_id: 'IAM-002' },
  { resource: 'old-key-user', rule_id: 'IAM-003' },
  { resource: 'account', rule_id: 'IAM-004' },
  { resource: 'prod-db', rule_id: 'RDS-001' },
  { resource: 'prod-db', rule_id: 'RDS-002' },
  { resource: 'account', rule_id: 'CT-001' },
  { resource: 'c53d1f55-a756-4c14-9a6e-e2f36b1a00e6', rule_id: 'KMS-001' }
];

export function getInitialCloudState(): CloudSnapshot {
  return {
    s3: [
      {
        name: 'public-logs-bucket',
        public_acl: true, // BAD S3-001
        encrypted: false, // BAD S3-002
        pab: false, // BAD S3-003
        versioning: true
      },
      {
        name: 'secure-data-bucket',
        public_acl: false, // GOOD
        encrypted: true, // GOOD
        pab: true, // GOOD
        versioning: true // GOOD
      },
      {
        name: 'backup-bucket-no-versioning',
        public_acl: false,
        encrypted: true,
        pab: true,
        versioning: false // BAD S3-004
      }
    ],
    sg: [
      {
        id: 'sg-01aa9901',
        group_name: 'default',
        description: 'default VPC security group',
        ip_permissions: []
      },
      {
        id: 'sg-02bb9902',
        group_name: 'open-ssh',
        description: 'SSH open to world',
        ip_permissions: [
          {
            protocol: 'tcp',
            from_port: 22,
            to_port: 22,
            cidr: '0.0.0.0/0' // BAD EC2-001
          }
        ]
      },
      {
        id: 'sg-03cc9903',
        group_name: 'open-all',
        description: 'All ports open',
        ip_permissions: [
          {
            protocol: '-1',
            cidr: '0.0.0.0/0' // BAD EC2-002
          }
        ]
      },
      {
        id: 'sg-04dd9904',
        group_name: 'web-sg',
        description: 'HTTPS only',
        ip_permissions: [
          {
            protocol: 'tcp',
            from_port: 443,
            to_port: 443,
            cidr: '0.0.0.0/0' // GOOD
          }
        ]
      }
    ],
    volumes: [
      {
        id: 'vol-4d38b140cfa399e55',
        encrypted: false, // BAD EC2-003
        size_gb: 8,
        az: 'us-east-1a'
      },
      {
        id: 'vol-7b11f15f62b4000f5',
        encrypted: true, // GOOD
        size_gb: 8,
        az: 'us-east-1a'
      }
    ],
    iam_users: [
      {
        name: 'dev-admin',
        mfa: false, // BAD IAM-001
        admin: true, // BAD IAM-002
        key_ages: []
      },
      {
        name: 'analyst-user',
        mfa: true, // GOOD
        admin: false, // GOOD
        key_ages: []
      },
      {
        name: 'old-key-user',
        mfa: true,
        admin: false,
        key_ages: [2479] // BAD IAM-003 (>90 days)
      }
    ],
    password_policy: {
      min_length: 6, // BAD IAM-004 (<14)
      require_symbols: false,
      require_numbers: false,
      require_uppercase: false,
      require_lowercase: false,
      max_age_days: 0,
      reuse_prevention: 0
    },
    rds: [
      {
        id: 'prod-db',
        publicly_accessible: true, // BAD RDS-001
        storage_encrypted: false, // BAD RDS-002
        engine: 'mysql',
        db_class: 'db.t3.micro'
      },
      {
        id: 'secure-db',
        publicly_accessible: false, // GOOD
        storage_encrypted: true, // GOOD
        engine: 'mysql',
        db_class: 'db.t3.micro'
      }
    ],
    trails: [], // BAD CT-001: no active multi-region trail
    kms: [
      {
        id: 'c53d1f55-a756-4c14-9a6e-e2f36b1a00e6',
        description: 'rotation OFF',
        rotation: false, // BAD KMS-001
        manager: 'CUSTOMER',
        state: 'Enabled',
        key_spec: 'SYMMETRIC_DEFAULT'
      },
      {
        id: '56341802-8890-4991-91fc-9b43c9ea973e',
        description: 'rotation ON',
        rotation: true, // GOOD
        manager: 'CUSTOMER',
        state: 'Enabled',
        key_spec: 'SYMMETRIC_DEFAULT'
      }
    ]
  };
}

export function getHardenedCloudState(): CloudSnapshot {
  return {
    s3: [
      { name: 'public-logs-bucket', public_acl: false, encrypted: true, pab: true, versioning: true },
      { name: 'secure-data-bucket', public_acl: false, encrypted: true, pab: true, versioning: true },
      { name: 'backup-bucket-no-versioning', public_acl: false, encrypted: true, pab: true, versioning: true }
    ],
    sg: [
      { id: 'sg-01aa9901', group_name: 'default', description: 'default VPC security group', ip_permissions: [] },
      { id: 'sg-02bb9902', group_name: 'open-ssh', description: 'SSH restricted to VPN bastion', ip_permissions: [{ protocol: 'tcp', from_port: 22, to_port: 22, cidr: '10.0.0.0/16' }] },
      { id: 'sg-03cc9903', group_name: 'open-all', description: 'Strict backend ingress only', ip_permissions: [{ protocol: 'tcp', from_port: 8080, to_port: 8080, cidr: '10.0.0.0/16' }] },
      { id: 'sg-04dd9904', group_name: 'web-sg', description: 'HTTPS only', ip_permissions: [{ protocol: 'tcp', from_port: 443, to_port: 443, cidr: '0.0.0.0/0' }] }
    ],
    volumes: [
      { id: 'vol-4d38b140cfa399e55', encrypted: true, size_gb: 8, az: 'us-east-1a' },
      { id: 'vol-7b11f15f62b4000f5', encrypted: true, size_gb: 8, az: 'us-east-1a' }
    ],
    iam_users: [
      { name: 'dev-admin', mfa: true, admin: false, key_ages: [] },
      { name: 'analyst-user', mfa: true, admin: false, key_ages: [] },
      { name: 'old-key-user', mfa: true, admin: false, key_ages: [14] }
    ],
    password_policy: {
      min_length: 16,
      require_symbols: true,
      require_numbers: true,
      require_uppercase: true,
      require_lowercase: true,
      max_age_days: 90,
      reuse_prevention: 5
    },
    rds: [
      { id: 'prod-db', publicly_accessible: false, storage_encrypted: true, engine: 'mysql', db_class: 'db.t3.micro' },
      { id: 'secure-db', publicly_accessible: false, storage_encrypted: true, engine: 'mysql', db_class: 'db.t3.micro' }
    ],
    trails: [
      { name: 'org-audit-trail', multi_region: true, logging: true, s3_bucket: 'audit-trail-logs-bucket' }
    ],
    kms: [
      { id: 'c53d1f55-a756-4c14-9a6e-e2f36b1a00e6', description: 'rotation ON', rotation: true, manager: 'CUSTOMER', state: 'Enabled', key_spec: 'SYMMETRIC_DEFAULT' },
      { id: '56341802-8890-4991-91fc-9b43c9ea973e', description: 'rotation ON', rotation: true, manager: 'CUSTOMER', state: 'Enabled', key_spec: 'SYMMETRIC_DEFAULT' }
    ]
  };
}
