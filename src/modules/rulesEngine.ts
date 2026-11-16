import { CloudSnapshot, Finding, SecurityGroupRule, Severity } from '../types/security';
import { RULES_CATALOG } from './rulesCatalog';

export const MAX_KEY_AGE_DAYS = 90;
export const MIN_PASSWORD_LENGTH = 14;

export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3
};

export function makeFinding(ruleId: string, resource: string): Finding {
  const rule = RULES_CATALOG[ruleId];
  if (!rule) {
    throw new Error(`Unknown rule ID: ${ruleId}`);
  }
  return {
    rule_id: rule.id,
    severity: rule.severity,
    service: rule.service,
    resource,
    description: rule.title,
    remediation: rule.remediation,
    cis: rule.cis || '-',
    nist: rule.nist
  };
}

export function riskyPermission(p: SecurityGroupRule): 'ALL' | 'ADMIN' | null {
  if (p.cidr !== '0.0.0.0/0') {
    return null;
  }
  if (p.protocol === '-1' || (p.from_port === 0 && p.to_port === 65535)) {
    return 'ALL';
  }
  if (p.from_port === 22 || p.from_port === 3389) {
    return 'ADMIN';
  }
  return null;
}

export function checkS3(buckets: CloudSnapshot['s3']): Finding[] {
  const findings: Finding[] = [];
  for (const b of buckets) {
    if (b.public_acl) {
      findings.push(makeFinding('S3-001', b.name));
    }
    if (!b.encrypted) {
      findings.push(makeFinding('S3-002', b.name));
    }
    if (!b.pab) {
      findings.push(makeFinding('S3-003', b.name));
    }
    if (!b.versioning) {
      findings.push(makeFinding('S3-004', b.name));
    }
  }
  return findings;
}

export function checkSG(groups: CloudSnapshot['sg']): Finding[] {
  const findings: Finding[] = [];
  for (const g of groups) {
    for (const p of g.ip_permissions) {
      const kind = riskyPermission(p);
      if (kind === 'ALL') {
        findings.push(makeFinding('EC2-002', g.group_name));
      } else if (kind === 'ADMIN') {
        findings.push(makeFinding('EC2-001', g.group_name));
      }
    }
  }
  return findings;
}

export function checkVolumes(volumes: CloudSnapshot['volumes']): Finding[] {
  return volumes
    .filter((v) => !v.encrypted)
    .map((v) => makeFinding('EC2-003', v.id));
}

export function checkIamUsers(users: CloudSnapshot['iam_users']): Finding[] {
  const findings: Finding[] = [];
  for (const u of users) {
    if (!u.mfa) {
      findings.push(makeFinding('IAM-001', u.name));
    }
    if (u.admin) {
      findings.push(makeFinding('IAM-002', u.name));
    }
    if (u.key_ages && u.key_ages.some((age) => age > MAX_KEY_AGE_DAYS)) {
      findings.push(makeFinding('IAM-003', u.name));
    }
  }
  return findings;
}

export function checkPasswordPolicy(policy: CloudSnapshot['password_policy']): Finding[] {
  if (!policy || policy.min_length < MIN_PASSWORD_LENGTH) {
    return [makeFinding('IAM-004', 'account')];
  }
  return [];
}

export function checkRDS(dbs: CloudSnapshot['rds']): Finding[] {
  const findings: Finding[] = [];
  for (const d of dbs) {
    if (d.publicly_accessible) {
      findings.push(makeFinding('RDS-001', d.id));
    }
    if (!d.storage_encrypted) {
      findings.push(makeFinding('RDS-002', d.id));
    }
  }
  return findings;
}

export function checkTrails(trails: CloudSnapshot['trails']): Finding[] {
  const hasActiveMultiRegion = trails.some((t) => t.multi_region && t.logging);
  if (hasActiveMultiRegion) {
    return [];
  }
  return [makeFinding('CT-001', 'account')];
}

export function checkKMS(keys: CloudSnapshot['kms']): Finding[] {
  return keys
    .filter((k) => k.manager === 'CUSTOMER' && k.state === 'Enabled' && !k.rotation)
    .map((k) => makeFinding('KMS-001', k.id));
}

export function auditCloud(data: CloudSnapshot): Finding[] {
  const allFindings = [
    ...checkS3(data.s3),
    ...checkSG(data.sg),
    ...checkVolumes(data.volumes),
    ...checkIamUsers(data.iam_users),
    ...checkPasswordPolicy(data.password_policy),
    ...checkRDS(data.rds),
    ...checkTrails(data.trails),
    ...checkKMS(data.kms)
  ];

  // Sort findings: CRITICAL -> HIGH -> MEDIUM -> LOW, then rule_id, then resource
  return allFindings.sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sevDiff !== 0) return sevDiff;
    const ruleDiff = a.rule_id.localeCompare(b.rule_id);
    if (ruleDiff !== 0) return ruleDiff;
    return a.resource.localeCompare(b.resource);
  });
}
