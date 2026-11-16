import { useState } from 'react';
import { CloudSnapshot, Finding, RemediationAction, ComplianceSummary } from '../types/security';
import { autoRemediate } from '../modules/remediation';
import { auditCloud } from '../modules/rulesEngine';
import { calculateSecurityScore, calculateGrade } from '../modules/scoring';
import { getComplianceSummary } from '../modules/compliance';
import { Wrench, CheckCircle, AlertTriangle, ArrowRight, ShieldCheck, Play, RotateCcw } from 'lucide-react';

interface Props {
  cloud: CloudSnapshot;
  onUpdateCloud: (updated: CloudSnapshot) => void;
  findings: Finding[];
  isDemoDatasetActive?: boolean;
  importedFileName?: string;
  onResetToDefault?: () => void;
}

export function AutoRemediationPanel({
  cloud,
  onUpdateCloud,
  findings,
  isDemoDatasetActive = false,
  importedFileName,
  onResetToDefault
}: Props) {
  const [remediationLog, setRemediationLog] = useState<RemediationAction[] | null>(null);
  const [beforeFindings, setBeforeFindings] = useState<Finding[] | null>(null);
  const [beforeScore, setBeforeScore] = useState<number | null>(null);
  const [beforeCompliance, setBeforeCompliance] = useState<ComplianceSummary | null>(null);

  const currentScore = calculateSecurityScore(findings);
  const currentGrade = calculateGrade(currentScore);
  const currentCompliance = getComplianceSummary(findings);

  const handleRunRemediation = () => {
    if (isDemoDatasetActive) return;

    // Snapshot current state as 'before'
    setBeforeFindings(findings);
    setBeforeScore(currentScore);
    setBeforeCompliance(currentCompliance);

    const { actions, updatedCloud } = autoRemediate(findings, cloud);
    setRemediationLog(actions);
    onUpdateCloud(updatedCloud);
  };

  const hasRun = remediationLog !== null && beforeScore !== null && beforeCompliance !== null;

  return (
    <div className="space-y-6">
      {/* Safety Notice if Demo Dataset is active */}
      {isDemoDatasetActive && (
        <div className="p-4 bg-amber-50 border border-amber-200 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-amber-900">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold">Auto-Remediation Safeguard: Disabled for Imported Demo Data</span>
              <p className="text-amber-800 mt-0.5">
                The active dataset was imported from demo file <code className="font-mono bg-amber-100 px-1 py-0.5 rounded">{importedFileName || 'file'}</code>.
                To prevent accidental state drift and maintain honest evaluation, automated remediation only runs on the built-in simulated AWS cloud.
              </p>
            </div>
          </div>
          {onResetToDefault && (
            <button
              onClick={onResetToDefault}
              className="px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg font-semibold shrink-0 transition-colors"
            >
              Reset to Simulated Cloud
            </button>
          )}
        </div>
      )}

      {/* Intro Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
              Auto-Remediation
            </span>
            <h2 className="text-lg font-bold text-slate-900">Automated Remediation & Impact Evaluation</h2>
          </div>
          <p className="text-xs text-slate-600 mt-1 max-w-3xl">
            Simulates self-healing cloud actions. Automatically mitigates safe configuration flaws (closing 0.0.0.0/0 firewalls,
            activating S3 encryption, enabling CloudTrail & KMS rotation) while deliberately escalating high-risk operations (MFA, admin privileges, storage swaps) to human engineers.
          </p>
        </div>

        <button
          onClick={handleRunRemediation}
          disabled={isDemoDatasetActive}
          className="px-4 py-2.5 bg-slate-900 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg text-xs font-semibold flex items-center gap-2 shrink-0 transition-colors shadow-sm"
          title={isDemoDatasetActive ? 'Disabled for imported demo files' : 'Execute automated fixes'}
        >
          <Play className="w-4 h-4 text-emerald-400 fill-emerald-400" />
          Execute Safe Auto-Remediation
        </button>
      </div>

      {/* Before vs After Impact Summary (when executed) */}
      {hasRun && (
        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-6">
          <div className="flex items-center justify-between border-b border-slate-200 pb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-900">
                Remediation Performance: Before vs After Impact
              </h3>
              <p className="text-xs text-slate-500">
                Live re-audit of the cloud environment following automated mitigations.
              </p>
            </div>
            <span className="text-xs font-mono font-bold px-2.5 py-1 bg-emerald-100 text-emerald-800 rounded">
              Posture Improved: +{currentScore - (beforeScore || 0)} Points
            </span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
              <span className="text-slate-500 block mb-1">Active Findings</span>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold font-mono text-slate-400 line-through">{beforeFindings?.length}</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-2xl font-bold font-mono text-slate-900">{findings.length}</span>
              </div>
              <span className="text-[11px] text-emerald-700 font-semibold block mt-1">
                -{(beforeFindings?.length || 0) - findings.length} resolved
              </span>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
              <span className="text-slate-500 block mb-1">Security Score</span>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold font-mono text-rose-500 line-through">{beforeScore}</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-2xl font-bold font-mono text-emerald-700">{currentScore}</span>
              </div>
              <span className="text-[11px] text-slate-600 block mt-1">Grade {calculateGrade(beforeScore || 0)} &rarr; Grade {currentGrade}</span>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
              <span className="text-slate-500 block mb-1">CIS Benchmark</span>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold font-mono text-slate-400 line-through">{beforeCompliance?.cis}%</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-2xl font-bold font-mono text-slate-900">{currentCompliance.cis}%</span>
              </div>
              <span className="text-[11px] text-emerald-700 font-semibold block mt-1">
                +{(currentCompliance.cis - (beforeCompliance?.cis || 0)).toFixed(1)}% compliance
              </span>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
              <span className="text-slate-500 block mb-1">NIST SP 800-53</span>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold font-mono text-slate-400 line-through">{beforeCompliance?.nist}%</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-2xl font-bold font-mono text-slate-900">{currentCompliance.nist}%</span>
              </div>
              <span className="text-[11px] text-emerald-700 font-semibold block mt-1">
                +{(currentCompliance.nist - (beforeCompliance?.nist || 0)).toFixed(1)}% compliance
              </span>
            </div>
          </div>

          {/* Visual severity distribution comparison */}
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg space-y-3">
            <span className="text-xs font-bold text-slate-700 uppercase tracking-wide block">
              Severity Distribution Shift
            </span>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => {
                const countBefore = beforeFindings?.filter((f) => f.severity === sev).length || 0;
                const countAfter = findings.filter((f) => f.severity === sev).length;
                return (
                  <div key={sev} className="p-2.5 bg-white border border-slate-200 rounded">
                    <span className="text-[11px] font-bold text-slate-500">{sev}</span>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="font-mono text-slate-400 line-through">{countBefore}</span>
                      <ArrowRight className="w-3 h-3 text-slate-400" />
                      <span className={`font-mono font-bold text-sm ${countAfter < countBefore ? 'text-emerald-700' : 'text-slate-800'}`}>
                        {countAfter}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Remediation Log Table */}
      {remediationLog && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 bg-slate-50 border-b border-slate-200 flex justify-between items-center text-xs">
            <span className="font-bold text-slate-900">
              Remediation Action Ledger ({remediationLog.length} Actions)
            </span>
            <div className="flex items-center gap-3 font-semibold text-xs">
              <span className="text-emerald-700">
                {remediationLog.filter((a) => a.status === 'FIXED').length} Automatically Fixed
              </span>
              <span>·</span>
              <span className="text-amber-700">
                {remediationLog.filter((a) => a.status === 'MANUAL').length} Manual Human Review
              </span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900 text-white uppercase text-[11px] font-semibold tracking-wider">
                <tr>
                  <th className="py-3 px-4 w-28">Rule ID</th>
                  <th className="py-3 px-4">Affected Resource</th>
                  <th className="py-3 px-4 text-center w-28">Action Status</th>
                  <th className="py-3 px-4">Mitigation Action Performed / Decision Rationale</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {remediationLog.map((action, idx) => (
                  <tr
                    key={idx}
                    className={action.status === 'FIXED' ? 'bg-emerald-50/50 hover:bg-emerald-50' : 'bg-yellow-50/50 hover:bg-yellow-50'}
                  >
                    <td className="py-3 px-4 font-mono font-bold text-slate-900">{action.rule_id}</td>
                    <td className="py-3 px-4 font-mono text-slate-800 font-semibold">{action.resource}</td>
                    <td className="py-3 px-4 text-center">
                      <span
                        className={`inline-block px-2.5 py-0.5 rounded font-mono font-bold text-[11px] ${
                          action.status === 'FIXED'
                            ? 'bg-emerald-200 text-emerald-950'
                            : 'bg-yellow-200 text-yellow-950'
                        }`}
                      >
                        {action.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-700 font-medium">{action.what_was_done}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Safety Matrix Explanation */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-2">
          <div className="flex items-center gap-2 font-bold text-emerald-900 text-sm">
            <CheckCircle className="w-4 h-4 text-emerald-600" />
            Safely Automated Mitigations
          </div>
          <p className="text-slate-600 leading-relaxed">
            Non-destructive configuration changes with deterministic idempotency are applied immediately:
          </p>
          <ul className="list-disc list-inside text-slate-700 space-y-1 pt-1 font-medium">
            <li>Removing 0.0.0.0/0 ingress on ports 22 and all protocols</li>
            <li>Enabling S3 Block Public Access, SSE-AES256 & bucket versioning</li>
            <li>Activating multi-region CloudTrail audit trail logging with dedicated S3 storage</li>
            <li>Enabling annual KMS customer key rotation</li>
            <li>Applying 14+ character password complexity policy</li>
            <li>Revoking public routing on RDS database instances</li>
          </ul>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-2">
          <div className="flex items-center gap-2 font-bold text-amber-900 text-sm">
            <AlertTriangle className="w-4 h-4 text-amber-600" />
            Human-in-the-Loop Safeguards (Manual Review)
          </div>
          <p className="text-slate-600 leading-relaxed">
            Potentially disruptive operations require human intervention to prevent production outage or lock-out:
          </p>
          <ul className="list-disc list-inside text-slate-700 space-y-1 pt-1 font-medium">
            <li>Physical MFA device enrolment (requires user verification device)</li>
            <li>Deprovisioning IAM administrative privileges (requires least-privilege role design)</li>
            <li>Programmatic access key rotation (requires application client updates)</li>
            <li>Encrypting existing EBS volumes (requires snapshot &gt; volume clone &gt; instance swap)</li>
            <li>Encrypting existing RDS instances (requires snapshot restore to new DB cluster)</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
