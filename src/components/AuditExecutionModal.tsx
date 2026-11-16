import { useState, useEffect } from 'react';
import {
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  X,
  ExternalLink,
  ArrowRight,
  Database,
  RefreshCw,
  Server,
  Layers,
  Sparkles,
  Lock
} from 'lucide-react';
import { Finding, ComplianceSummary } from '../types/security';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  isScanning: boolean;
  clientEmail: string;
  accountId: string;
  findings: Finding[];
  score: number;
  grade: string;
  compliance: ComplianceSummary;
  onNavigateTab: (tab: string) => void;
  isDemoDataset?: boolean;
  datasetFileName?: string;
}

interface ScanStep {
  service: string;
  target: string;
  status: 'pending' | 'scanning' | 'completed';
  issuesFound: number;
}

export function AuditExecutionModal({
  isOpen,
  onClose,
  isScanning,
  clientEmail,
  accountId,
  findings,
  score,
  grade,
  compliance,
  onNavigateTab,
  isDemoDataset,
  datasetFileName
}: Props) {
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [isCompleted, setIsCompleted] = useState<boolean>(false);

  const initialSteps: ScanStep[] = [
    { service: 'Amazon S3', target: 'Buckets, ACLs, Default Encryption, Block Public Access', status: 'pending', issuesFound: 0 },
    { service: 'Amazon EC2 & VPC', target: 'Security Groups, Ports 22/3389, 0.0.0.0/0 Wildcards', status: 'pending', issuesFound: 0 },
    { service: 'Amazon EBS', target: 'Root & Data Storage Volumes Encryption', status: 'pending', issuesFound: 0 },
    { service: 'AWS IAM', target: 'MFA Enforcement, AdministratorAccess Policies, 90+ Day Keys', status: 'pending', issuesFound: 0 },
    { service: 'Amazon RDS', target: 'Public Network Accessibility & Storage Encryption', status: 'pending', issuesFound: 0 },
    { service: 'AWS CloudTrail', target: 'Multi-Region Trails & Management Event Logging', status: 'pending', issuesFound: 0 },
    { service: 'AWS KMS', target: 'Customer Master Key (CMK) Annual Rotation', status: 'pending', issuesFound: 0 }
  ];

  const [steps, setSteps] = useState<ScanStep[]>(initialSteps);

  useEffect(() => {
    if (!isOpen) {
      setScanProgress(0);
      setCurrentStepIndex(0);
      setIsCompleted(false);
      setSteps(initialSteps);
      return;
    }

    // Always run an engaging scan sequence when opened
    setIsCompleted(false);
    setScanProgress(15);
    setSteps(initialSteps.map((s, idx) => (idx === 0 ? { ...s, status: 'scanning' } : s)));

    let current = 15;
    const interval = setInterval(() => {
      current += 25;
      if (current >= 100) {
        clearInterval(interval);
        setScanProgress(100);
        setIsCompleted(true);
        // Populate counts for each service
        setSteps(
          initialSteps.map((s) => {
            let count = 0;
            if (s.service.includes('S3')) count = findings.filter((f) => f.service === 'S3').length;
            else if (s.service.includes('EC2')) count = findings.filter((f) => f.service === 'EC2').length;
            else if (s.service.includes('EBS')) count = findings.filter((f) => f.service === 'EBS').length;
            else if (s.service.includes('IAM')) count = findings.filter((f) => f.service === 'IAM').length;
            else if (s.service.includes('RDS')) count = findings.filter((f) => f.service === 'RDS').length;
            else if (s.service.includes('CloudTrail')) count = findings.filter((f) => f.service === 'CloudTrail').length;
            else if (s.service.includes('KMS')) count = findings.filter((f) => f.service === 'KMS').length;
            return {
              ...s,
              status: 'completed',
              issuesFound: count
            };
          })
        );
      } else {
        setScanProgress(current);
      }
    }, 120);

    return () => clearInterval(interval);
  }, [isOpen, findings]);

  if (!isOpen) return null;

  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.severity === 'LOW').length;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-white border border-slate-200 rounded-2xl max-w-3xl w-full shadow-2xl overflow-hidden flex flex-col my-auto max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-900 text-white">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center border ${
              isCompleted ? 'bg-slate-800 text-emerald-400 border-slate-700' : 'bg-slate-800 text-amber-400 border-slate-700'
            }`}>
              {!isCompleted ? (
                <RefreshCw className="w-5 h-5 animate-spin text-amber-400" />
              ) : (
                <ShieldAlert className="w-5 h-5 text-emerald-400" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white">
                  {!isCompleted
                    ? (isDemoDataset ? 'Analyzing Imported Audit Dataset...' : 'Executing Cloud Security Audit...')
                    : (isDemoDataset ? `Imported Audit Posture Analyzed (${datasetFileName || 'Demo File'})` : 'Audit Run Completed — Findings Discovered')}
                </h3>
                {isDemoDataset ? (
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/30 text-amber-300 border border-amber-500/40">
                    DEMO DATASET
                  </span>
                ) : (
                  <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    Account: {accountId}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400">
                {isDemoDataset ? (
                  <span>Source: <span className="font-mono text-amber-300">{datasetFileName || 'Imported File'}</span> · Engine: 15-Rule Security Benchmark Matrix</span>
                ) : (
                  <span>Target: <span className="font-mono text-slate-300">{clientEmail}</span> · Engine: 15-Rule CIS/NIST Auditor</span>
                )}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Progress bar */}
        <div className="w-full bg-slate-100 h-1.5 overflow-hidden">
          <div
            className={`h-full transition-all duration-300 ${
              isCompleted ? 'bg-emerald-500' : 'bg-slate-900'
            }`}
            style={{ width: `${scanProgress}%` }}
          />
        </div>

        {/* Body */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1">
          {/* Summary Score Banner */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-slate-50 border border-slate-200 p-3.5 rounded-xl">
              <span className="text-[10px] uppercase font-bold text-slate-500 block">Security Posture</span>
              <div className="flex items-baseline gap-1 mt-1 font-mono">
                <span className="text-2xl font-black text-slate-900">{score}</span>
                <span className="text-xs text-slate-500">/ 100</span>
                <span className={`ml-2 text-xs font-bold px-1.5 py-0.5 rounded ${
                  score >= 70 ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                }`}>
                  Grade {grade}
                </span>
              </div>
            </div>

            <div className="bg-slate-50 border border-slate-200 p-3.5 rounded-xl">
              <span className="text-[10px] uppercase font-bold text-slate-500 block">Total Violations</span>
              <div className="flex items-baseline gap-1 mt-1 font-mono">
                <span className="text-2xl font-black text-rose-600">{findings.length}</span>
                <span className="text-xs text-slate-500">Flaws</span>
              </div>
            </div>

            <div className="bg-slate-50 border border-slate-200 p-3.5 rounded-xl">
              <span className="text-[10px] uppercase font-bold text-slate-500 block">CIS Benchmark v1.4</span>
              <div className="flex items-baseline gap-1 mt-1 font-mono">
                <span className="text-2xl font-black text-slate-900">{compliance.cis}%</span>
                <span className="text-xs text-slate-500">Passing</span>
              </div>
            </div>

            <div className="bg-slate-50 border border-slate-200 p-3.5 rounded-xl">
              <span className="text-[10px] uppercase font-bold text-slate-500 block">NIST SP 800-53</span>
              <div className="flex items-baseline gap-1 mt-1 font-mono">
                <span className="text-2xl font-black text-slate-900">{compliance.nist}%</span>
                <span className="text-xs text-slate-500">Passing</span>
              </div>
            </div>
          </div>

          {/* Severity Breakdown Strip */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-500 font-sans font-semibold">Severity Breakdown:</span>
            <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-800 font-bold">
              {criticalCount} Critical
            </span>
            <span className="px-2 py-0.5 rounded bg-orange-100 text-orange-800 font-bold">
              {highCount} High
            </span>
            <span className="px-2 py-0.5 rounded bg-yellow-100 text-yellow-800 font-bold">
              {mediumCount} Medium
            </span>
            <span className="px-2 py-0.5 rounded bg-blue-100 text-blue-800 font-bold">
              {lowCount} Low
            </span>
          </div>

          {/* Services Scanned Checklist */}
          <div className="space-y-2">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center justify-between">
              <span>Cloud Services Audited ({steps.length})</span>
              <span className="font-mono text-[11px] text-slate-500">All 7 Services Scanned</span>
            </h4>
            <div className="border border-slate-200 rounded-xl divide-y divide-slate-100 overflow-hidden bg-white">
              {steps.map((st, i) => (
                <div key={i} className="px-4 py-2.5 flex items-center justify-between text-xs hover:bg-slate-50 transition-colors">
                  <div className="flex items-center gap-3">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    <div>
                      <span className="font-bold text-slate-900">{st.service}</span>
                      <span className="text-slate-500 text-[11px] ml-2 font-mono">({st.target})</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {st.issuesFound > 0 ? (
                      <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200">
                        {st.issuesFound} {st.issuesFound === 1 ? 'Violation' : 'Violations'}
                      </span>
                    ) : (
                      <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                        Clean
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Discovered Findings Preview */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600">
                Discovered Security Findings ({findings.length})
              </h4>
              <button
                onClick={() => {
                  onNavigateTab('rules');
                  onClose();
                }}
                className="text-xs text-slate-900 hover:text-black font-bold underline flex items-center gap-1"
              >
                <span>Open Full Interactive Rules Table</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="border border-slate-200 rounded-xl overflow-hidden max-h-56 overflow-y-auto divide-y divide-slate-100 bg-white">
              {findings.map((f, idx) => (
                <div
                  key={idx}
                  className="p-3 flex items-start justify-between gap-3 hover:bg-slate-50 transition-colors text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-slate-900 bg-slate-100 px-1.5 py-0.5 rounded text-[11px]">
                        {f.rule_id}
                      </span>
                      <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                        f.severity === 'CRITICAL'
                          ? 'bg-rose-600 text-white'
                          : f.severity === 'HIGH'
                          ? 'bg-orange-500 text-white'
                          : f.severity === 'MEDIUM'
                          ? 'bg-yellow-500 text-white'
                          : 'bg-blue-600 text-white'
                      }`}>
                        {f.severity}
                      </span>
                      <span className="font-mono text-slate-600 text-[11px]">{f.service}</span>
                      <span className="text-slate-300">·</span>
                      <span className="font-mono text-slate-500 text-[11px] truncate max-w-xs">{f.resource}</span>
                    </div>
                    <p className="text-slate-800 text-[11px] font-medium leading-relaxed">
                      {f.description}
                    </p>
                  </div>

                  <button
                    onClick={() => {
                      onNavigateTab('resolver');
                      onClose();
                    }}
                    className="shrink-0 text-[11px] font-semibold text-slate-700 hover:text-slate-950 px-2.5 py-1 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors flex items-center gap-1"
                  >
                    <span>Fix</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-4 border-t border-slate-200 bg-slate-50 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="text-xs text-slate-500 font-mono">
            Audit recorded in SQLite database · audit_runs table
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <button
              onClick={() => {
                onNavigateTab('rules');
                onClose();
              }}
              className="flex-1 sm:flex-none px-4 py-2 text-xs font-semibold bg-white border border-slate-300 hover:bg-slate-100 text-slate-800 rounded-lg transition-colors shadow-2xs"
            >
              View in Rules Engine
            </button>
            <button
              onClick={() => {
                onNavigateTab('resolver');
                onClose();
              }}
              className="flex-1 sm:flex-none px-4 py-2 text-xs font-semibold bg-white border border-slate-300 hover:bg-slate-100 text-slate-800 rounded-lg transition-colors shadow-2xs"
            >
              Inspect & Resolve
            </button>
            <button
              onClick={() => {
                onNavigateTab('remediation');
                onClose();
              }}
              className="flex-1 sm:flex-none px-4 py-2 text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-white rounded-lg transition-colors shadow-xs flex items-center gap-1.5"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Auto-Remediate</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
