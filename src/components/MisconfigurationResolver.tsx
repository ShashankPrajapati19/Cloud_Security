import { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Wrench,
  Terminal,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Copy,
  Check,
  ExternalLink,
  ShieldCheck,
  Search,
  Sparkles
} from 'lucide-react';
import { Finding } from '../types/security';

interface MisconfigurationRecord {
  rule_id: string;
  title: string;
  service: string;
  severity: string;
  cis_control: string | null;
  nist_control: string;
  mitre_attack_technique: string;
  flaw_explanation: string;
  attack_scenario: string;
  remediation_summary: string;
  remediation_steps: string[];
  aws_cli_command: string;
  terraform_snippet: string;
  verification_command: string;
  is_auto_remediable: boolean;
}

interface ExploitResult {
  status: 'VULNERABLE' | 'MITIGATED_AND_SECURE';
  is_exploitable: boolean;
  rule_id: string;
  resource: string;
  severity?: string;
  exploit_log: string;
  exfiltrated_evidence: string;
  mitre_technique: string;
  remediation_advice: string;
  aws_cli_fix: string;
  terraform_fix: string;
  verification_command: string;
}

interface Props {
  currentEmail: string;
  findings: Finding[];
  onAuditUpdated: () => void;
}

export function MisconfigurationResolver({ currentEmail, findings, onAuditUpdated }: Props) {
  const [kbList, setKbList] = useState<MisconfigurationRecord[]>([]);
  const [selectedRuleId, setSelectedRuleId] = useState<string>('S3-001');
  const [activeRecord, setActiveRecord] = useState<MisconfigurationRecord | null>(null);
  const [isLoadingRecord, setIsLoadingRecord] = useState(false);
  const [copiedCli, setCopiedCli] = useState(false);
  const [copiedTf, setCopiedTf] = useState(false);
  const [copiedVerify, setCopiedVerify] = useState(false);

  // Exploit simulation probe state
  const [isProbing, setIsProbing] = useState(false);
  const [exploitResult, setExploitResult] = useState<ExploitResult | null>(null);
  const [isRemediatingThis, setIsRemediatingThis] = useState(false);

  // Load KB catalog on mount
  useEffect(() => {
    fetch('/api/misconfigurations')
      .then(async (res) => {
        if (!res.ok) throw new Error(`Misconfiguration catalog request failed (${res.status}).`);
        return res.json();
      })
      .then((data) => {
        if (data.success && data.misconfigurations) {
          setKbList(data.misconfigurations);
        } else {
          throw new Error(data.error || 'Invalid misconfiguration catalog response.');
        }
      })
      .catch((err) => console.error('Failed to load misconfigurations catalog:', err));
  }, []);

  // Fetch full details whenever selectedRuleId changes
  useEffect(() => {
    if (!selectedRuleId) return;
    setIsLoadingRecord(true);
    setExploitResult(null);
    fetch(`/api/misconfigurations/${selectedRuleId}`)
      .then(async (res) => {
        if (!res.ok) throw new Error(`Rule request failed (${res.status}).`);
        return res.json();
      })
      .then((data) => {
        if (data.success && data.misconfiguration) {
          setActiveRecord(data.misconfiguration);
        } else {
          throw new Error(data.error || 'Invalid rule response.');
        }
      })
      .catch((err) => console.error(`Failed to load rule ${selectedRuleId}:`, err))
      .finally(() => setIsLoadingRecord(false));
  }, [selectedRuleId]);

  // Check if currently active in findings
  const activeFinding = findings.find((f) => f.rule_id === selectedRuleId);
  const isCurrentlyVulnerable = !!activeFinding;

  // Run threat actor exploit simulation probe
  const handleRunExploitProbe = async () => {
    setIsProbing(true);
    setExploitResult(null);
    try {
      const res = await fetch('/api/exploit-probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: currentEmail,
          rule_id: selectedRuleId,
          resource: activeFinding?.resource
        })
      });
      if (!res.ok) throw new Error(`Exploit probe request failed (${res.status}).`);
      const data = await res.json();
      if (data.success === false) throw new Error(data.error || 'Exploit probe failed.');
      setExploitResult(data);
    } catch (err) {
      console.error('Exploit probe failed:', err);
    } finally {
      setIsProbing(false);
    }
  };

  // Remediate this client's infrastructure via backend API
  const handleRemediateSingle = async () => {
    setIsRemediatingThis(true);
    try {
      const res = await fetch(`/api/remediate/${encodeURIComponent(currentEmail)}`, {
        method: 'POST'
      });
      if (!res.ok) throw new Error(`Remediation request failed (${res.status}).`);
      const data = await res.json();
      if (data.success) {
        onAuditUpdated();
        // Re-run probe to prove it is mitigated
        setTimeout(() => {
          handleRunExploitProbe();
        }, 300);
      } else {
        throw new Error(data.error || 'Remediation request returned an invalid response.');
      }
    } catch (err) {
      console.error('Remediation call failed:', err);
    } finally {
      setIsRemediatingThis(false);
    }
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm space-y-6">
      {/* Header bar */}
      <div className="p-5 bg-slate-900 text-white flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-800 text-emerald-400 border border-slate-700">
              Live Inspector & Resolver
            </span>
            <h2 className="text-base font-bold text-white">Cloud Misconfiguration Intelligence Engine</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Pick any misconfiguration to analyze the technical root cause, attack blast radius, and execute guided or automated resolution.
          </p>
        </div>

        {/* Misconfiguration Selector Dropdown */}
        <div className="flex items-center gap-2 shrink-0">
          <label className="text-xs font-semibold text-slate-300 whitespace-nowrap">Target Flaw:</label>
          <select
            value={selectedRuleId}
            onChange={(e) => setSelectedRuleId(e.target.value)}
            className="text-xs font-mono font-semibold px-3 py-2 bg-slate-800 text-white border border-slate-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-emerald-400"
          >
            {kbList.map((rule) => {
              const hasFlawInClient = findings.some((f) => f.rule_id === rule.rule_id);
              return (
                <option key={rule.rule_id} value={rule.rule_id}>
                  {hasFlawInClient ? '🔴 ' : '🟢 '} {rule.rule_id} — {rule.title.substring(0, 48)}...
                </option>
              );
            })}
          </select>
        </div>
      </div>

      {isLoadingRecord || !activeRecord ? (
        <div className="p-12 text-center text-xs text-slate-500 font-mono">
          Loading misconfiguration resolution intelligence from database...
        </div>
      ) : (
        <div className="p-6 space-y-6">
          {/* Target Status Banner */}
          <div
            className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs ${
              isCurrentlyVulnerable
                ? 'bg-rose-50/80 border-rose-200 text-rose-950'
                : 'bg-emerald-50/80 border-emerald-200 text-emerald-950'
            }`}
          >
            <div className="flex items-start sm:items-center gap-3">
              <div
                className={`w-9 h-9 rounded-lg flex items-center justify-center font-bold font-mono text-xs shrink-0 ${
                  isCurrentlyVulnerable ? 'bg-rose-600 text-white' : 'bg-emerald-600 text-white'
                }`}
              >
                {activeRecord.severity}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sm">
                    {activeRecord.rule_id}: {activeRecord.title}
                  </span>
                  <span
                    className={`font-mono text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                      isCurrentlyVulnerable ? 'bg-rose-200 text-rose-950' : 'bg-emerald-200 text-emerald-950'
                    }`}
                  >
                    {isCurrentlyVulnerable ? 'LIVE FLAW DETECTED' : 'CURRENTLY HARDENED'}
                  </span>
                </div>
                <p className="text-slate-600 text-xs mt-0.5">
                  Target: <strong className="font-mono">{activeFinding?.resource || 'Simulated AWS Resource'}</strong> · Service: <strong>{activeRecord.service}</strong> · CIS: <strong className="font-mono">{activeRecord.cis_control || 'N/A'}</strong> · NIST: <strong className="font-mono">{activeRecord.nist_control}</strong> · MITRE: <strong className="font-mono">{activeRecord.mitre_attack_technique}</strong>
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={handleRunExploitProbe}
                disabled={isProbing}
                className="px-3.5 py-2 text-xs font-semibold bg-slate-900 hover:bg-slate-800 disabled:opacity-50 text-white rounded-lg transition-colors flex items-center gap-1.5 shadow-xs"
              >
                <Play className={`w-3.5 h-3.5 text-amber-400 fill-amber-400 ${isProbing ? 'animate-pulse' : ''}`} />
                <span>{isProbing ? 'Probing Target...' : 'Simulate Exploit Attack'}</span>
              </button>
            </div>
          </div>

          {/* Live Exploit Probe Terminal Output */}
          {exploitResult && (
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs space-y-3 shadow-md">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 text-slate-400">
                <span className="flex items-center gap-2 text-white font-bold">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  Red Team Exploit Simulation Terminal Output
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    exploitResult.status === 'VULNERABLE' ? 'bg-rose-900 text-rose-200' : 'bg-emerald-900 text-emerald-200'
                  }`}
                >
                  STATUS: {exploitResult.status}
                </span>
              </div>

              <pre className="text-emerald-400 leading-relaxed overflow-x-auto whitespace-pre-wrap select-all py-1">
                {exploitResult.exploit_log}
              </pre>

              {exploitResult.is_exploitable && (
                <div className="p-3 bg-rose-950/60 border border-rose-800/80 rounded-lg text-rose-200 space-y-2">
                  <div className="font-bold flex items-center gap-2 text-rose-300">
                    <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                    <span>Exploit Successful — Compromised Proof-of-Concept:</span>
                  </div>
                  <div className="p-2 bg-black/60 rounded text-amber-300 font-mono text-xs break-all">
                    {exploitResult.exfiltrated_evidence}
                  </div>
                  <div className="flex items-center justify-between pt-1">
                    <span className="text-[11px] text-rose-300">
                      MITRE ATT&CK: {exploitResult.mitre_technique}
                    </span>
                    <button
                      onClick={handleRemediateSingle}
                      disabled={isRemediatingThis}
                      className="px-3 py-1.5 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 text-white rounded font-bold text-xs flex items-center gap-1.5 transition-colors"
                    >
                      <Wrench className="w-3.5 h-3.5" />
                      {isRemediatingThis ? 'Applying Fix...' : 'Remediate This Flaw in DB'}
                    </button>
                  </div>
                </div>
              )}

              {!exploitResult.is_exploitable && (
                <div className="p-3 bg-emerald-950/60 border border-emerald-800/80 rounded-lg text-emerald-200 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>Exploit Blocked: Resource is securely configured in SQLite database.</span>
                  </div>
                  <span className="font-bold text-emerald-300">PASS</span>
                </div>
              )}
            </div>
          )}

          {/* Section 1: "WHAT IS THE MISCONFIGURATION?" */}
          <div className="space-y-4">
            <div className="flex items-center gap-2 border-b border-slate-200 pb-2">
              <ShieldAlert className="w-4 h-4 text-slate-800" />
              <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                1. What is the Misconfiguration?
              </h3>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2 text-xs">
                <span className="font-bold text-slate-900 block text-xs">
                  Technical Root Cause & Flaw Architecture
                </span>
                <p className="text-slate-700 leading-relaxed font-medium">
                  {activeRecord.flaw_explanation}
                </p>
              </div>

              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2 text-xs">
                <span className="font-bold text-slate-900 block text-xs">
                  Adversary Attack Scenario & Blast Radius
                </span>
                <p className="text-slate-700 leading-relaxed whitespace-pre-line font-medium">
                  {activeRecord.attack_scenario}
                </p>
              </div>
            </div>
          </div>

          {/* Section 2: "HOW TO RESOLVE IT?" */}
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 pb-2">
              <div className="flex items-center gap-2">
                <Wrench className="w-4 h-4 text-slate-800" />
                <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                  2. How to Resolve It?
                </h3>
              </div>
              <span className="text-xs font-mono font-semibold text-slate-500">
                {activeRecord.is_auto_remediable ? '⚡ Auto-Remediable Available' : '⚠️ Manual Review Required'}
              </span>
            </div>

            {/* Step-by-Step Resolution Workflow */}
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl text-xs space-y-3">
              <span className="font-bold text-slate-900 block">
                Standard Remediation Steps (AWS Management Console)
              </span>
              <ol className="list-decimal list-inside space-y-1.5 text-slate-800">
                {activeRecord.remediation_steps.map((step, idx) => (
                  <li key={idx} className="leading-relaxed">
                    {step}
                  </li>
                ))}
              </ol>
            </div>

            {/* AWS CLI Command Box */}
            <div className="p-4 bg-slate-950 text-slate-300 font-mono text-xs rounded-xl space-y-2 shadow-xs">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 text-slate-400">
                <span className="font-bold text-white flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                  AWS CLI Remediation Command
                </span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(activeRecord.aws_cli_command);
                    setCopiedCli(true);
                    setTimeout(() => setCopiedCli(false), 2000);
                  }}
                  className="hover:text-white flex items-center gap-1 text-[11px] bg-slate-900 px-2.5 py-1 rounded border border-slate-800 transition-colors"
                >
                  {copiedCli ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedCli ? 'Copied' : 'Copy Command'}
                </button>
              </div>
              <pre className="text-emerald-400 leading-relaxed overflow-x-auto select-all py-1">
                {activeRecord.aws_cli_command}
              </pre>
            </div>

            {/* Terraform (HCL) Snippet Box */}
            <div className="p-4 bg-slate-950 text-slate-300 font-mono text-xs rounded-xl space-y-2 shadow-xs">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 text-slate-400">
                <span className="font-bold text-white flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-indigo-400" />
                  Infrastructure as Code (Terraform / HCL Patch)
                </span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(activeRecord.terraform_snippet);
                    setCopiedTf(true);
                    setTimeout(() => setCopiedTf(false), 2000);
                  }}
                  className="hover:text-white flex items-center gap-1 text-[11px] bg-slate-900 px-2.5 py-1 rounded border border-slate-800 transition-colors"
                >
                  {copiedTf ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedTf ? 'Copied' : 'Copy HCL'}
                </button>
              </div>
              <pre className="text-indigo-300 leading-relaxed overflow-x-auto select-all py-1">
                {activeRecord.terraform_snippet}
              </pre>
            </div>

            {/* Verification Command */}
            <div className="p-3 bg-slate-100 border border-slate-200 rounded-xl text-xs space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-800 text-[11px] uppercase tracking-wide">
                  Post-Remediation Verification Command
                </span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(activeRecord.verification_command);
                    setCopiedVerify(true);
                    setTimeout(() => setCopiedVerify(false), 2000);
                  }}
                  className="text-slate-600 hover:text-slate-900 text-[11px] font-semibold underline flex items-center gap-1"
                >
                  {copiedVerify ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="p-2 bg-white border border-slate-300 rounded font-mono text-slate-900 break-all select-all">
                {activeRecord.verification_command}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
