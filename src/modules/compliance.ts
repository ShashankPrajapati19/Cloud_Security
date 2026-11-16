import { ControlRow, Finding, ComplianceSummary } from '../types/security';
import { RULES_CATALOG } from './rulesCatalog';

export const CIS_CONTROL_TITLES: Record<string, string> = {
  '1.8': 'Ensure password policy requires minimum length of 14 or greater',
  '1.10': 'Ensure multi-factor authentication (MFA) is enabled for all IAM users',
  '1.14': 'Ensure access keys are rotated every 90 days or less',
  '1.16': 'Ensure IAM policies that allow full administrative privileges are not attached',
  '2.1.1': 'Ensure S3 Bucket Policy is set to deny unencrypted HTTP requests and encryption is enabled',
  '2.1.5': 'Ensure that S3 Buckets are configured with Block Public Access and private ACLs',
  '2.2.1': 'Ensure EBS volume encryption is enabled in all regions',
  '2.3.1': 'Ensure that encryption-at-rest is enabled for RDS instances',
  '2.3.3': 'Ensure that public access is not enabled for RDS database instances',
  '3.1': 'Ensure CloudTrail is enabled in all regions with active log delivery',
  '3.8': 'Ensure rotation for customer created symmetric KMS CMKs is enabled',
  '5.2': 'Ensure no security groups allow ingress from 0.0.0.0/0 to administrative ports or all traffic'
};

export const NIST_CONTROL_TITLES: Record<string, string> = {
  'AC-3': 'Access Enforcement: S3 Object Access and Public Isolation',
  'AC-6': 'Least Privilege: Restrict Excessive Administrative Privileges',
  'AU-2': 'Event Logging: Multi-Region System Activity Auditing (CloudTrail)',
  'CP-9': 'Information System Backup: Object Versioning & Resilience',
  'IA-2(1)': 'Identification & Authentication: Multi-Factor Authentication for Privileged Users',
  'IA-5': 'Authenticator Management: Cryptographic Key Lifecycle and 90-Day Rotation',
  'IA-5(1)': 'Password-Based Authentication: Strict Password Length & Complexity Enforcement',
  'SC-7': 'Boundary Protection: Perimeter Firewalls and Ingress Filtering',
  'SC-12': 'Cryptographic Key Establishment and Management: Key Rotation',
  'SC-28': 'Protection of Information at Rest: Cryptographic Storage Protection'
};

export function buildControlTable(findings: Finding[], framework: 'cis' | 'nist'): ControlRow[] {
  const controlsMap: Record<string, string[]> = {};

  for (const [ruleId, rule] of Object.entries(RULES_CATALOG)) {
    const ctrl = framework === 'cis' ? rule.cis : rule.nist;
    if (ctrl) {
      if (!controlsMap[ctrl]) {
        controlsMap[ctrl] = [];
      }
      controlsMap[ctrl].push(ruleId);
    }
  }

  const rows: ControlRow[] = [];

  for (const [control, ruleIds] of Object.entries(controlsMap)) {
    const hits = findings.filter((f) => ruleIds.includes(f.rule_id));
    rows.push({
      control,
      rules: ruleIds,
      status: hits.length > 0 ? 'FAIL' : 'PASS',
      failing_resources: hits.length,
      framework,
      title: framework === 'cis' ? CIS_CONTROL_TITLES[control] : NIST_CONTROL_TITLES[control]
    });
  }

  // Sort logically (e.g. 1.8 before 1.10, or AC-3 before AC-6)
  return rows.sort((a, b) => {
    return a.control.localeCompare(b.control, undefined, { numeric: true, sensitivity: 'base' });
  });
}

export function calculateCompliancePercent(table: ControlRow[]): number {
  if (table.length === 0) return 100.0;
  const passed = table.filter((row) => row.status === 'PASS').length;
  return Number(((passed / table.length) * 100).toFixed(1));
}

export function getComplianceSummary(findings: Finding[]): ComplianceSummary {
  const cisTable = buildControlTable(findings, 'cis');
  const nistTable = buildControlTable(findings, 'nist');
  return {
    cis: calculateCompliancePercent(cisTable),
    nist: calculateCompliancePercent(nistTable)
  };
}
