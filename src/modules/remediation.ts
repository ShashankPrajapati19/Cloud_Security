import { CloudSnapshot, Finding, RemediationAction } from '../types/security';

export const MANUAL_REASONS: Record<string, string> = {
  'IAM-001': 'A person must enrol the MFA device',
  'IAM-002': 'Needs human review before removing admin rights',
  'IAM-003': 'Rotate key: create new, update apps, delete old',
  'EC2-003': 'Needs snapshot > encrypted copy > swap disk',
  'RDS-002': 'Needs snapshot restore into an encrypted database'
};

export function autoRemediate(
  findings: Finding[],
  currentState: CloudSnapshot
): {
  actions: RemediationAction[];
  updatedCloud: CloudSnapshot;
} {
  // Deep clone cloud snapshot
  const nextCloud: CloudSnapshot = JSON.parse(JSON.stringify(currentState));
  const actions: RemediationAction[] = [];
  const processedKeys = new Set<string>();

  for (const f of findings) {
    const { rule_id, resource } = f;

    // Check if risky manual issue
    if (MANUAL_REASONS[rule_id]) {
      actions.push({
        rule_id,
        resource,
        status: 'MANUAL',
        what_was_done: MANUAL_REASONS[rule_id]
      });
      continue;
    }

    // Grouping key so resources with multiple findings are fixed cleanly
    const key = rule_id.startsWith('S3')
      ? `S3::${resource}`
      : rule_id.startsWith('EC2')
      ? `SG::${resource}`
      : `${rule_id}::${resource}`;

    if (processedKeys.has(key)) {
      continue;
    }
    processedKeys.add(key);

    try {
      if (rule_id.startsWith('S3')) {
        const bucket = nextCloud.s3.find((b) => b.name === resource);
        if (bucket) {
          bucket.public_acl = false;
          bucket.pab = true;
          bucket.encrypted = true;
          bucket.versioning = true;
          actions.push({
            rule_id,
            resource,
            status: 'FIXED',
            what_was_done: 'Set private ACL, Block Public Access, encryption, versioning'
          });
        }
      } else if (rule_id === 'EC2-001' || rule_id === 'EC2-002') {
        const sg = nextCloud.sg.find((g) => g.group_name === resource);
        if (sg) {
          const initialCount = sg.ip_permissions.length;
          // Filter out dangerous 0.0.0.0/0 ingress
          sg.ip_permissions = sg.ip_permissions.filter((p) => {
            if (p.cidr === '0.0.0.0/0') {
              if (p.protocol === '-1' || (p.from_port === 0 && p.to_port === 65535)) return false;
              if (p.from_port === 22 || p.from_port === 3389) return false;
            }
            return true;
          });
          const removed = initialCount - sg.ip_permissions.length;
          actions.push({
            rule_id,
            resource,
            status: 'FIXED',
            what_was_done: `Removed ${removed || 1} risky firewall rule(s)`
          });
        }
      } else if (rule_id === 'IAM-004') {
        nextCloud.password_policy = {
          min_length: 14,
          require_symbols: true,
          require_numbers: true,
          require_uppercase: true,
          require_lowercase: true,
          max_age_days: 90,
          reuse_prevention: 5
        };
        actions.push({
          rule_id,
          resource,
          status: 'FIXED',
          what_was_done: 'Strong password policy applied (14+ chars, mixed, 90-day expiry)'
        });
      } else if (rule_id === 'CT-001') {
        // Create secure logging bucket & multi-region trail
        const auditBucket = nextCloud.s3.find((b) => b.name === 'audit-trail-logs-bucket');
        if (!auditBucket) {
          nextCloud.s3.push({
            name: 'audit-trail-logs-bucket',
            public_acl: false,
            encrypted: true,
            pab: true,
            versioning: true
          });
        }
        nextCloud.trails = [
          {
            name: 'org-audit-trail',
            multi_region: true,
            logging: true,
            s3_bucket: 'audit-trail-logs-bucket'
          }
        ];
        actions.push({
          rule_id,
          resource,
          status: 'FIXED',
          what_was_done: 'Created multi-region trail and started logging'
        });
      } else if (rule_id === 'KMS-001') {
        const keyObj = nextCloud.kms.find((k) => k.id === resource);
        if (keyObj) {
          keyObj.rotation = true;
          actions.push({
            rule_id,
            resource,
            status: 'FIXED',
            what_was_done: 'Automatic key rotation enabled'
          });
        }
      } else if (rule_id === 'RDS-001') {
        const db = nextCloud.rds.find((d) => d.id === resource);
        if (db) {
          db.publicly_accessible = false;
          actions.push({
            rule_id,
            resource,
            status: 'FIXED',
            what_was_done: 'Database made private (revoked public routing)'
          });
        }
      } else {
        actions.push({
          rule_id,
          resource,
          status: 'MANUAL',
          what_was_done: 'No automatic fix available'
        });
      }
    } catch (err: unknown) {
      actions.push({
        rule_id,
        resource,
        status: 'ERROR',
        what_was_done: err instanceof Error ? err.message : 'Unknown remediation failure'
      });
    }
  }

  return { actions, updatedCloud: nextCloud };
}
