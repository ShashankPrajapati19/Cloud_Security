import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { getInitialCloudState } from '../modules/cloudSimulation';

const DATA_DIR = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'cloudguard.db');
export const db = new Database(DB_PATH);

// Enable WAL mode for high concurrency & speed
db.pragma('journal_mode = WAL');

// Initialize database schema
export function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS clients (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      company TEXT NOT NULL,
      cloud_provider TEXT NOT NULL DEFAULT 'AWS',
      account_id TEXT NOT NULL,
      region TEXT NOT NULL,
      environment TEXT NOT NULL,
      created_at TEXT NOT NULL,
      cloud_state TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS misconfigurations_kb (
      rule_id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      service TEXT NOT NULL,
      severity TEXT NOT NULL,
      cis_control TEXT,
      nist_control TEXT NOT NULL,
      mitre_attack_technique TEXT NOT NULL,
      flaw_explanation TEXT NOT NULL,
      attack_scenario TEXT NOT NULL,
      remediation_summary TEXT NOT NULL,
      remediation_steps TEXT NOT NULL,
      aws_cli_command TEXT NOT NULL,
      terraform_snippet TEXT NOT NULL,
      verification_command TEXT NOT NULL,
      is_auto_remediable INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS audit_runs (
      id TEXT PRIMARY KEY,
      client_email TEXT NOT NULL,
      score INTEGER NOT NULL,
      grade TEXT NOT NULL,
      findings_count INTEGER NOT NULL,
      cis_compliance REAL NOT NULL,
      nist_compliance REAL NOT NULL,
      findings_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      audit_type TEXT NOT NULL,
      FOREIGN KEY (client_email) REFERENCES clients(email) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS remediation_logs (
      id TEXT PRIMARY KEY,
      client_email TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      resource TEXT NOT NULL,
      action_status TEXT NOT NULL,
      details TEXT NOT NULL,
      executed_at TEXT NOT NULL
    );
  `);

  seedClients();
  seedMisconfigurations();
}

function seedClients() {
  const count = db.prepare('SELECT COUNT(*) as count FROM clients').get() as { count: number };
  if (count.count > 0) return;

  const initialCloud = getInitialCloudState();

  const insertClient = db.prepare(`
    INSERT INTO clients (id, email, name, company, cloud_provider, account_id, region, environment, created_at, cloud_state)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const clients = [
    {
      id: 'client_01',
      email: 'kakuverma385@gmail.com',
      name: 'Shashank Prajapati',
      company: 'Enterprise Security Architecture Lab',
      cloud_provider: 'AWS',
      account_id: '714305265226',
      region: 'us-east-1',
      environment: 'Production Core AWS',
      created_at: new Date('2026-10-01T08:00:00Z').toISOString(),
      cloud_state: JSON.stringify(initialCloud)
    },
    {
      id: 'client_02',
      email: 'ciso@fintech-vault.io',
      name: 'Elena Rostova',
      company: 'FinPay Global Payments Inc.',
      cloud_provider: 'AWS',
      account_id: '892144701290',
      region: 'us-east-1',
      environment: 'PCI-DSS Banking Enclave',
      created_at: new Date('2026-10-05T09:30:00Z').toISOString(),
      cloud_state: JSON.stringify(initialCloud)
    },
    {
      id: 'client_03',
      email: 'devops-lead@healthtech-apex.org',
      name: 'Marcus Chen',
      company: 'Apex Health Systems & Clinical Care',
      cloud_provider: 'AWS',
      account_id: '334190827116',
      region: 'us-west-2',
      environment: 'HIPAA Patient EHR Cloud',
      created_at: new Date('2026-10-10T14:15:00Z').toISOString(),
      cloud_state: JSON.stringify(initialCloud)
    },
    {
      id: 'client_04',
      email: 'security@globex-retail.com',
      name: 'Sarah Jenkins',
      company: 'Globex Omnichannel Retailers',
      cloud_provider: 'AWS',
      account_id: '551098234419',
      region: 'eu-west-1',
      environment: 'E-Commerce Production Fleet',
      created_at: new Date('2026-10-12T11:00:00Z').toISOString(),
      cloud_state: JSON.stringify(initialCloud)
    }
  ];

  for (const c of clients) {
    insertClient.run(
      c.id,
      c.email,
      c.name,
      c.company,
      c.cloud_provider,
      c.account_id,
      c.region,
      c.environment,
      c.created_at,
      c.cloud_state
    );
  }
}

function seedMisconfigurations() {
  const count = db.prepare('SELECT COUNT(*) as count FROM misconfigurations_kb').get() as { count: number };
  if (count.count > 0) return;

  const insertRule = db.prepare(`
    INSERT INTO misconfigurations_kb (
      rule_id, title, service, severity, cis_control, nist_control,
      mitre_attack_technique, flaw_explanation, attack_scenario,
      remediation_summary, remediation_steps, aws_cli_command,
      terraform_snippet, verification_command, is_auto_remediable
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const rules = [
    {
      rule_id: 'S3-001',
      title: 'S3 bucket is open to the public (ACL grant to AllUsers)',
      service: 'S3',
      severity: 'CRITICAL',
      cis_control: '2.1.5',
      nist_control: 'AC-3',
      mitre_attack_technique: 'T1530 - Data from Cloud Storage Object',
      flaw_explanation: 'The bucket Access Control List (ACL) explicitly includes a grant to the URI http://acs.amazonaws.com/groups/global/AllUsers. Anyone with an internet connection can anonymously list bucket contents and download sensitive objects without credentials.',
      attack_scenario: '1. Attacker runs open-source reconnaissance tools (aws-s3-scanner, Pacu).\n2. Discovers s3://public-logs-bucket is publicly readable.\n3. Pulls down application database backups, internal system logs, and .env credentials.\n4. Obtains production database connection strings and secret access tokens.',
      remediation_summary: 'Revoke the public ACL grant immediately and enforce S3 Block Public Access across all 4 parameters.',
      remediation_steps: JSON.stringify([
        'Open AWS Management Console and navigate to S3.',
        'Select bucket "public-logs-bucket" and navigate to Permissions tab.',
        'Under Access Control List (ACL), click Edit and remove the "Everyone (public access)" grant.',
        'Enable all 4 "Block public access (bucket settings)" toggles and save changes.'
      ]),
      aws_cli_command: 'aws s3api put-bucket-acl --bucket public-logs-bucket --acl private\naws s3api put-public-access-block --bucket public-logs-bucket --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
      terraform_snippet: `resource "aws_s3_bucket_public_access_block" "public_logs_protect" {
  bucket = aws_s3_bucket.public_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "public_logs_acl" {
  bucket = aws_s3_bucket.public_logs.id
  acl    = "private"
}`,
      verification_command: 'aws s3api get-public-access-block --bucket public-logs-bucket',
      is_auto_remediable: 1
    },
    {
      rule_id: 'S3-002',
      title: 'S3 bucket has no default server-side encryption enabled',
      service: 'S3',
      severity: 'HIGH',
      cis_control: '2.1.1',
      nist_control: 'SC-28',
      mitre_attack_technique: 'T1530 - Data from Cloud Storage Object',
      flaw_explanation: 'Bucket lacks automatic Server-Side Encryption (SSE) configuration. Data written to the bucket without explicit encryption headers will reside in plaintext on underlying storage volumes, violating compliance standards.',
      attack_scenario: 'Unencrypted assets risk exposure if backup media, secondary replications, or decommissioning processes are compromised without cryptographic access control barriers.',
      remediation_summary: 'Configure default SSE-S3 (AES256) or SSE-KMS on the target bucket.',
      remediation_steps: JSON.stringify([
        'Navigate to the S3 bucket in the AWS console.',
        'Select the Properties tab and find "Default encryption".',
        'Choose "Server-side encryption with Amazon S3 managed keys (SSE-S3)" or AWS KMS.',
        'Save changes. All future uploaded objects will be encrypted at rest automatically.'
      ]),
      aws_cli_command: 'aws s3api put-bucket-encryption --bucket public-logs-bucket --server-side-encryption-configuration \'{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}\'',
      terraform_snippet: `resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_crypto" {
  bucket = aws_s3_bucket.public_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}`,
      verification_command: 'aws s3api get-bucket-encryption --bucket public-logs-bucket',
      is_auto_remediable: 1
    },
    {
      rule_id: 'S3-003',
      title: 'S3 Block Public Access is not fully enabled (All 4 settings required)',
      service: 'S3',
      severity: 'MEDIUM',
      cis_control: '2.1.5',
      nist_control: 'AC-3',
      mitre_attack_technique: 'T1530 - Data from Cloud Storage Object',
      flaw_explanation: 'One or more of the 4 Amazon S3 Block Public Access safeguards are set to false. Even if the current ACL is private, future policy updates or IAM scripts can accidentally expose the bucket.',
      attack_scenario: 'A developer or automated CI/CD pipeline pushes a bucket policy with "Principal": "*" for troubleshooting, inadvertently making production storage world-readable because public block guardrails were disabled.',
      remediation_summary: 'Turn on BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.',
      remediation_steps: JSON.stringify([
        'In S3 Console, select bucket -> Permissions.',
        'Click Edit under Block Public Access (bucket settings).',
        'Check all four boxes: Block public ACLs, Ignore public ACLs, Block public bucket policies, Restrict public buckets.',
        'Confirm by typing "confirm" in the modal.'
      ]),
      aws_cli_command: 'aws s3api put-public-access-block --bucket public-logs-bucket --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
      terraform_snippet: `resource "aws_s3_bucket_public_access_block" "block_all" {
  bucket = aws_s3_bucket.secure_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
      verification_command: 'aws s3api get-public-access-block --bucket public-logs-bucket',
      is_auto_remediable: 1
    },
    {
      rule_id: 'S3-004',
      title: 'S3 bucket versioning is disabled (Data loss & ransomware vulnerability)',
      service: 'S3',
      severity: 'LOW',
      cis_control: null,
      nist_control: 'CP-9',
      mitre_attack_technique: 'T1485 - Data Destruction',
      flaw_explanation: 'Object versioning is turned off. Objects overwritten or deleted cannot be recovered, increasing vulnerability to accidental deletion or malicious ransomware wiping.',
      attack_scenario: 'An attacker with write permissions replaces sensitive objects with empty or corrupted files. Without versioning enabled, previous clean copies are permanently lost.',
      remediation_summary: 'Enable object versioning on the S3 bucket.',
      remediation_steps: JSON.stringify([
        'Open S3 Console and select the target bucket.',
        'Under the Properties tab, locate "Bucket Versioning".',
        'Click Edit and select "Enable". Save changes.'
      ]),
      aws_cli_command: 'aws s3api put-bucket-versioning --bucket backup-bucket-no-versioning --versioning-configuration Status=Enabled',
      terraform_snippet: `resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.backup_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}`,
      verification_command: 'aws s3api get-bucket-versioning --bucket backup-bucket-no-versioning',
      is_auto_remediable: 1
    },
    {
      rule_id: 'EC2-001',
      title: 'SSH (port 22) or RDP (port 3389) is open to the entire internet (0.0.0.0/0)',
      service: 'EC2',
      severity: 'HIGH',
      cis_control: '5.2',
      nist_control: 'SC-7',
      mitre_attack_technique: 'T1190 - Exploit Public-Facing Application',
      flaw_explanation: 'Security Group ingress rule authorizes TCP port 22 or 3389 from CIDR 0.0.0.0/0. This exposes instance management ports to automated scanners and credential stuffing bots globally.',
      attack_scenario: '1. Attacker continuously scans IPv4 address ranges with Shodan / Masscan.\n2. Identifies open SSH listener on instance.\n3. Launches dictionary brute-force attack or exploits OpenSSH vulnerability (e.g. regreSSHion).\n4. Gains interactive shell access to virtual machine.',
      remediation_summary: 'Restrict administrative ingress to corporate VPN CIDRs, or deploy AWS Systems Manager (SSM) Session Manager to eliminate open ports.',
      remediation_steps: JSON.stringify([
        'Open EC2 Management Console -> Security Groups.',
        'Select security group "open-ssh" and click "Edit inbound rules".',
        'Delete the rule allowing Port 22 from 0.0.0.0/0.',
        'Replace with specific trusted IP address (e.g. 10.0.0.0/16 or corporate office IP/32).'
      ]),
      aws_cli_command: 'aws ec2 revoke-security-group-ingress --group-name open-ssh --protocol tcp --port 22 --cidr 0.0.0.0/0',
      terraform_snippet: `# BAD: Ingress from 0.0.0.0/0
# FIX: Restrict to VPC or use AWS SSM Session Manager (no open ingress ports needed!)
resource "aws_security_group_rule" "ssh_restricted" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/16"] # Corporate Bastion only
  security_group_id = aws_security_group.app_sg.id
}`,
      verification_command: 'aws ec2 describe-security-groups --group-names open-ssh --query "SecurityGroups[*].IpPermissions"',
      is_auto_remediable: 1
    },
    {
      rule_id: 'EC2-002',
      title: 'ALL ports and protocols are open to 0.0.0.0/0 (Completely open firewall)',
      service: 'EC2',
      severity: 'CRITICAL',
      cis_control: '5.2',
      nist_control: 'SC-7',
      mitre_attack_technique: 'T1190 - Exploit Public-Facing Application',
      flaw_explanation: 'The security group contains an ingress rule with IpProtocol "-1" (All traffic) from 0.0.0.0/0. This bypasses stateful packet inspection for every port from 0 to 65535.',
      attack_scenario: 'Attacker probes instance and finds unauthenticated internal management services (Redis, Docker daemon on 2375, Prometheus metrics, debug ports). Attacker gains remote code execution instantly.',
      remediation_summary: 'Immediately revoke the wildcard rule and allow only explicit application ports (e.g. 443 for HTTPS).',
      remediation_steps: JSON.stringify([
        'Go to EC2 Console -> Security Groups -> select "open-all".',
        'Click "Edit inbound rules".',
        'Locate rule: "All traffic" / "All" / "All" / "0.0.0.0/0".',
        'Click Delete, then save rules.'
      ]),
      aws_cli_command: 'aws ec2 revoke-security-group-ingress --group-name open-all --ip-permissions \'[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]\'',
      terraform_snippet: `resource "aws_security_group" "web_tier" {
  name        = "web-sg"
  description = "HTTPS only from internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`,
      verification_command: 'aws ec2 describe-security-groups --group-names open-all --query "SecurityGroups[*].IpPermissions"',
      is_auto_remediable: 1
    },
    {
      rule_id: 'EC2-003',
      title: 'EBS volume storage is not encrypted at rest',
      service: 'EBS',
      severity: 'MEDIUM',
      cis_control: '2.2.1',
      nist_control: 'SC-28',
      mitre_attack_technique: 'T1530 - Data from Cloud Storage Object',
      flaw_explanation: 'Elastic Block Store (EBS) volume is configured with Encrypted=false. Stored operating system blocks, temporary files, and application caches are unencrypted on disk.',
      attack_scenario: 'If an unencrypted snapshot is made and accidentally shared publicly, or during forensic volume analysis, all disk data is unencrypted and readable.',
      remediation_summary: 'Create snapshot of volume, copy snapshot with KMS encryption enabled, and restore new encrypted volume.',
      remediation_steps: JSON.stringify([
        'Stop the attached EC2 instance to preserve filesystem integrity.',
        'Create a snapshot of the unencrypted EBS volume.',
        'Copy the snapshot and check "Enable encryption" with your KMS key.',
        'Create a new volume from the encrypted snapshot.',
        'Attach the new encrypted volume to instance and restart.'
      ]),
      aws_cli_command: 'aws ec2 create-snapshot --volume-id vol-4d38b140cfa399e55 --description "Pre-encryption snapshot"\n# Copy snapshot with encryption:\naws ec2 copy-snapshot --source-region us-east-1 --source-snapshot-id <snap-id> --encrypted --kms-key-id default',
      terraform_snippet: `resource "aws_ebs_volume" "encrypted_vol" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
  kms_key_id        = aws_kms_key.storage_key.arn

  tags = {
    Name = "EncryptedAppStorage"
  }
}`,
      verification_command: 'aws ec2 describe-volumes --volume-ids vol-4d38b140cfa399e55 --query "Volumes[*].Encrypted"',
      is_auto_remediable: 0
    },
    {
      rule_id: 'IAM-001',
      title: 'IAM user has no Multi-Factor Authentication (MFA) enabled',
      service: 'IAM',
      severity: 'HIGH',
      cis_control: '1.10',
      nist_control: 'IA-2(1)',
      mitre_attack_technique: 'T1078.004 - Cloud Accounts',
      flaw_explanation: 'The user account relies solely on single-factor passwords. If the user\'s credentials are leaked, phished, or reused, an attacker gains direct access without secondary authentication challenge.',
      attack_scenario: '1. Attacker harvests credentials through phishing or public credential dumps.\n2. Signs into AWS Console as dev-admin.\n3. Because no MFA is required, login succeeds immediately.\n4. Attacker deploys cryptominers or exfiltrates intellectual property.',
      remediation_summary: 'Enrol a hardware token or virtual TOTP device (Google Authenticator / YubiKey) for the user.',
      remediation_steps: JSON.stringify([
        'Open IAM Console -> Users -> select "dev-admin".',
        'Click Security credentials tab.',
        'Under Multi-factor authentication (MFA), click "Assign MFA device".',
        'Choose Authenticator app, scan QR code, and submit 2 consecutive TOTP codes.'
      ]),
      aws_cli_command: 'aws iam create-virtual-mfa-device --virtual-mfa-device-name dev-admin-mfa --outfile QRCode.png --bootstrap-method QRCodePNG\naws iam enable-mfa-device --user-name dev-admin --serial-number <mfa-arn> --authentication-code1 123456 --authentication-code2 654321',
      terraform_snippet: `# Enforce MFA via IAM policy condition:
resource "aws_iam_policy" "enforce_mfa" {
  name        = "EnforceMFA"
  description = "Denies all access unless user is authenticated with MFA"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyAllExceptListedIfNoMFA"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}`,
      verification_command: 'aws iam list-mfa-devices --user-name dev-admin',
      is_auto_remediable: 0
    },
    {
      rule_id: 'IAM-002',
      title: 'IAM user has full administrative privileges attached (*:*)',
      service: 'IAM',
      severity: 'CRITICAL',
      cis_control: '1.16',
      nist_control: 'AC-6',
      mitre_attack_technique: 'T1078.004 - Cloud Accounts',
      flaw_explanation: 'The user has an attached policy containing Action: "*" on Resource: "*". This gives total unrestricted control over every AWS service, billing, IAM, and infrastructure, violating the Principle of Least Privilege.',
      attack_scenario: 'A compromised dev-admin API key allows an attacker to delete CloudTrail audit logs, create backdoor admin accounts, encrypt database backups with attacker-controlled keys, and wipe production infrastructure.',
      remediation_summary: 'Detach AdministratorAccess and replace with a targeted, role-based policy restricting actions to required job functions.',
      remediation_steps: JSON.stringify([
        'Navigate to IAM Console -> Users -> dev-admin.',
        'Under Permissions tab, locate policy with Action: "*", Resource: "*".',
        'Click Detach / Remove.',
        'Attach a scoped job-specific policy or assign user to a designated Developer group.'
      ]),
      aws_cli_command: 'aws iam detach-user-policy --user-name dev-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess',
      terraform_snippet: `# Principle of Least Privilege: Specific read-only or developer policy instead of *:*
resource "aws_iam_user_policy_attachment" "developer_policy" {
  user       = aws_iam_user.dev_user.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}`,
      verification_command: 'aws iam list-attached-user-policies --user-name dev-admin',
      is_auto_remediable: 0
    },
    {
      rule_id: 'IAM-003',
      title: 'Active IAM access key is older than 90 days (Stale credential risk)',
      service: 'IAM',
      severity: 'MEDIUM',
      cis_control: '1.14',
      nist_control: 'IA-5',
      mitre_attack_technique: 'T1078.004 - Cloud Accounts',
      flaw_explanation: 'The access key was created over 90 days ago. Long-lived credentials significantly increase the likelihood of credential leakage via developer workstations, CI/CD logs, or commit histories.',
      attack_scenario: 'A developer committed an access key into a private repository 6 months ago. The repository is cloned or accessed by a contractor, providing persistent unmonitored API access.',
      remediation_summary: 'Issue a new key, test it in client applications, and deactivate/delete the expired key.',
      remediation_steps: JSON.stringify([
        'Create a secondary access key for user "old-key-user".',
        'Update configuration files and CI/CD pipelines with the new key.',
        'Deactivate the old key and monitor application traffic for 48 hours.',
        'Permanently delete the old key.'
      ]),
      aws_cli_command: 'aws iam create-access-key --user-name old-key-user\n# After updating apps, delete the expired key:\naws iam update-access-key --user-name old-key-user --access-key-id <old-key-id> --status Inactive\naws iam delete-access-key --user-name old-key-user --access-key-id <old-key-id>',
      terraform_snippet: `# Use AWS IAM Roles for EC2 / ECS / Lambda (IAM Instance Profiles) to eliminate static keys completely!
resource "aws_iam_instance_profile" "app_profile" {
  name = "app-iam-profile"
  role = aws_iam_role.app_role.name
}`,
      verification_command: 'aws iam list-access-keys --user-name old-key-user',
      is_auto_remediable: 0
    },
    {
      rule_id: 'IAM-004',
      title: 'Account password policy is too weak (Length < 14, missing complexity)',
      service: 'IAM',
      severity: 'MEDIUM',
      cis_control: '1.8',
      nist_control: 'IA-5(1)',
      mitre_attack_technique: 'T1110 - Brute Force',
      flaw_explanation: 'Account password policy requires fewer than 14 characters or does not mandate symbols, numbers, and uppercase characters. Short passwords are easily cracked via modern GPU hash tables.',
      attack_scenario: 'Attacker leverages rainbow tables and wordlists to crack 6-character user passwords within minutes, compromising console login.',
      remediation_summary: 'Set MinimumPasswordLength=14 and enforce symbols, numbers, uppercase characters, and 90-day expiration.',
      remediation_steps: JSON.stringify([
        'Open IAM Console -> Account settings.',
        'Under Password policy, click Edit.',
        'Set minimum password length to at least 14.',
        'Require at least one uppercase letter, one lowercase letter, one number, and one non-alphanumeric character.',
        'Enable password expiration (90 days) and prevent password reuse (5).'
      ]),
      aws_cli_command: 'aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 5',
      terraform_snippet: `resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 5
}`,
      verification_command: 'aws iam get-account-password-policy',
      is_auto_remediable: 1
    },
    {
      rule_id: 'RDS-001',
      title: 'RDS database instance is publicly accessible from internet',
      service: 'RDS',
      severity: 'HIGH',
      cis_control: '2.3.3',
      nist_control: 'SC-7',
      mitre_attack_technique: 'T1190 - Exploit Public-Facing Application',
      flaw_explanation: 'Database has PubliclyAccessible=true, allocating an internet-routable IP address. Databases should never be exposed to public networks directly.',
      attack_scenario: '1. Attacker finds open MySQL port 3306 on Amazon RDS endpoint.\n2. Performs automated password spray against "admin" or "root" user.\n3. Gains direct SQL execution access and dumps entire customer database.',
      remediation_summary: 'Modify DB instance to PubliclyAccessible=false and locate database inside isolated private VPC subnets.',
      remediation_steps: JSON.stringify([
        'Open Amazon RDS Console -> Databases.',
        'Select instance "prod-db" and click Modify.',
        'Under Connectivity, expand Additional configuration.',
        'Change Public access setting from "Publicly accessible" to "Not publicly accessible".',
        'Apply changes immediately.'
      ]),
      aws_cli_command: 'aws rds modify-db-instance --db-instance-identifier prod-db --no-publicly-accessible --apply-immediately',
      terraform_snippet: `resource "aws_db_instance" "secure_database" {
  identifier          = "prod-db"
  allocated_storage   = 20
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  publicly_accessible = false # MUST be false!
  db_subnet_group_name = aws_db_subnet_group.private_subnets.name
}`,
      verification_command: 'aws rds describe-db-instances --db-instance-identifier prod-db --query "DBInstances[*].PubliclyAccessible"',
      is_auto_remediable: 1
    },
    {
      rule_id: 'RDS-002',
      title: 'RDS database storage volume is not encrypted with KMS',
      service: 'RDS',
      severity: 'HIGH',
      cis_control: '2.3.1',
      nist_control: 'SC-28',
      mitre_attack_technique: 'T1530 - Data from Cloud Storage Object',
      flaw_explanation: 'StorageEncrypted is set to false. Underlying database tablespaces, automated backups, read replicas, and transaction logs are stored unencrypted.',
      attack_scenario: 'Physical media theft or compromised database volume snapshots give attackers unencrypted access to raw SQL tables and transaction history.',
      remediation_summary: 'Create snapshot, copy snapshot with KMS encryption enabled, and restore database from encrypted snapshot.',
      remediation_steps: JSON.stringify([
        'Create a manual snapshot of database "prod-db".',
        'Copy the snapshot and enable KMS encryption.',
        'Restore a new RDS instance from the encrypted snapshot.',
        'Update application database endpoint DNS / connection strings to point to the new encrypted instance.'
      ]),
      aws_cli_command: 'aws rds create-db-snapshot --db-instance-identifier prod-db --db-snapshot-identifier prod-db-unencrypted-snap\naws rds copy-db-snapshot --source-db-snapshot-identifier prod-db-unencrypted-snap --target-db-snapshot-identifier prod-db-encrypted-snap --kms-key-id default',
      terraform_snippet: `resource "aws_db_instance" "encrypted_db" {
  identifier        = "prod-db"
  allocated_storage = 20
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  storage_encrypted = true
  kms_key_id        = aws_kms_key.db_key.arn
}`,
      verification_command: 'aws rds describe-db-instances --db-instance-identifier prod-db --query "DBInstances[*].StorageEncrypted"',
      is_auto_remediable: 0
    },
    {
      rule_id: 'CT-001',
      title: 'No active multi-region CloudTrail audit trail configured with logging',
      service: 'CloudTrail',
      severity: 'HIGH',
      cis_control: '3.1',
      nist_control: 'AU-2',
      mitre_attack_technique: 'T1562.001 - Impair Defenses: Disable Cloud Logs',
      flaw_explanation: 'No multi-region CloudTrail trail exists with active logging enabled. Security operations cannot detect unauthorized API calls, privilege escalation, or resource tampering.',
      attack_scenario: 'An attacker conducts unauthorized reconnaissance and data theft. Because CloudTrail is disabled, zero forensic audit logs are produced, leaving defenders completely blind.',
      remediation_summary: 'Create a multi-region trail attached to an encrypted, private S3 bucket and start logging immediately.',
      remediation_steps: JSON.stringify([
        'Open CloudTrail Console -> Trails -> Create trail.',
        'Enter trail name "org-audit-trail".',
        'Create a new dedicated S3 bucket with encryption enabled.',
        'Enable "Apply trail to all regions" and start logging.'
      ]),
      aws_cli_command: 'aws s3 mb s3://audit-trail-logs-bucket\naws cloudtrail create-trail --name org-audit-trail --s3-bucket-name audit-trail-logs-bucket --is-multi-region-trail\naws cloudtrail start-logging --name org-audit-trail',
      terraform_snippet: `resource "aws_cloudtrail" "main_audit" {
  name                          = "org-audit-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
}`,
      verification_command: 'aws cloudtrail get-trail-status --name org-audit-trail',
      is_auto_remediable: 1
    },
    {
      rule_id: 'KMS-001',
      title: 'KMS customer managed encryption key rotation is disabled',
      service: 'KMS',
      severity: 'LOW',
      cis_control: '3.8',
      nist_control: 'SC-12',
      mitre_attack_technique: 'T1552 - Unsecured Credentials',
      flaw_explanation: 'Automatic annual key rotation is turned off for customer-managed symmetric key. Cryptographic best practices require regular key material rotation to limit ciphertext volume per key.',
      attack_scenario: 'If key material is ever exposed or subject to cryptanalysis, indefinitely reusing the same key allows decryption of all past and future ciphertexts.',
      remediation_summary: 'Enable automatic key rotation on the KMS key.',
      remediation_steps: JSON.stringify([
        'Open AWS KMS Console -> Customer managed keys.',
        'Select the target key -> Key rotation tab.',
        'Check "Automatically rotate this KMS key every year". Save.'
      ]),
      aws_cli_command: 'aws kms enable-key-rotation --key-id c53d1f55-a756-4c14-9a6e-e2f36b1a00e6',
      terraform_snippet: `resource "aws_kms_key" "app_key" {
  description             = "App master encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}`,
      verification_command: 'aws kms get-key-rotation-status --key-id c53d1f55-a756-4c14-9a6e-e2f36b1a00e6',
      is_auto_remediable: 1
    }
  ];

  for (const r of rules) {
    insertRule.run(
      r.rule_id,
      r.title,
      r.service,
      r.severity,
      r.cis_control,
      r.nist_control,
      r.mitre_attack_technique,
      r.flaw_explanation,
      r.attack_scenario,
      r.remediation_summary,
      r.remediation_steps,
      r.aws_cli_command,
      r.terraform_snippet,
      r.verification_command,
      r.is_auto_remediable
    );
  }
}
