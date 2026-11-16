import { useState, useEffect, useMemo, useCallback } from 'react';
import { getInitialCloudState } from './modules/cloudSimulation';
import { auditCloud } from './modules/rulesEngine';
import { calculateSecurityScore, calculateGrade } from './modules/scoring';
import { getComplianceSummary } from './modules/compliance';
import { encryptAuditSummary } from './modules/crypto';
import {
  CloudSnapshot,
  Finding,
  EncryptedSummaryPayload,
  ImportedAuditDataset
} from './types/security';
import { Header } from './components/Header';
import { EncryptedSummaryVault } from './components/EncryptedSummaryVault';
import { ClientEmailSelector, ClientProfile } from './components/ClientEmailSelector';
import { MisconfigurationResolver } from './components/MisconfigurationResolver';
import { Module1Simulation } from './components/Module1Simulation';
import { Module2Collectors } from './components/Module2Collectors';
import { Module3RuleEngine } from './components/Module3RuleEngine';
import { Module4Compliance } from './components/Module4Compliance';
import { Module5Scoring } from './components/Module5Scoring';
import { AutoRemediationPanel } from './components/AutoRemediationPanel';
import { ReportExportView } from './components/ReportExportView';
import { ImportAuditModal } from './components/ImportAuditModal';
import { AuditExecutionModal } from './components/AuditExecutionModal';
import {
  ShieldAlert,
  Server,
  ArrowUpRight,
  UploadCloud,
  RotateCcw,
  Sparkles,
  Terminal,
  Database,
  ArrowRight,
  CheckCircle2,
  Filter,
  X,
  Zap
} from 'lucide-react';

export default function App() {
  const [cloud, setCloud] = useState<CloudSnapshot>(getInitialCloudState);
  const [importedDataset, setImportedDataset] = useState<ImportedAuditDataset | null>(null);
  const [importNotice, setImportNotice] = useState<{
    visible: boolean;
    fileName: string;
    findingsCount: number;
    sourceType: string;
    time: string;
  } | null>(null);
  const [isImportModalOpen, setIsImportModalOpen] = useState<boolean>(false);
  const [isAuditModalOpen, setIsAuditModalOpen] = useState<boolean>(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [summaryFindingFilter, setSummaryFindingFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');
  const [activeTab, setActiveTab] = useState<string>('summary');
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [encryptedPayload, setEncryptedPayload] = useState<EncryptedSummaryPayload | null>(null);

  // Clients database state
  const [clients, setClients] = useState<ClientProfile[]>([]);
  const [currentEmail, setCurrentEmail] = useState<string>('kakuverma385@gmail.com');
  const [isLoadingClients, setIsLoadingClients] = useState<boolean>(false);

  // Fetch all clients from backend
  const fetchClients = useCallback(async () => {
    setIsLoadingClients(true);
    try {
      const res = await fetch('/api/clients');
      if (!res.ok) {
        throw new Error(`Client list request failed (${res.status}).`);
      }
      const data = await res.json();
      if (data.success && data.clients) {
        setClients(data.clients);
        setApiError(null);
      } else {
        throw new Error(data.error || 'Client list request returned an invalid response.');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to load clients from the backend.';
      setApiError(message);
      console.error('Failed to fetch clients from backend:', err);
    } finally {
      setIsLoadingClients(false);
    }
  }, []);

  // Fetch specific client's cloud state from backend database
  const fetchClientCloud = useCallback(async (email: string) => {
    try {
      const res = await fetch(`/api/clients/${encodeURIComponent(email)}`);
      if (!res.ok) {
        throw new Error(`Client request failed (${res.status}).`);
      }
      const data = await res.json();
      if (data.success && data.cloud_state) {
        setCloud(data.cloud_state);
        setImportedDataset(null);
        setApiError(null);
      } else {
        throw new Error(data.error || 'Client request returned an invalid response.');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : `Unable to load cloud state for ${email}.`;
      setApiError(message);
      console.error(`Failed to load cloud state for ${email}:`, err);
    }
  }, []);

  // Initial load: fetch clients list and initial client cloud state
  useEffect(() => {
    fetchClients();
    fetchClientCloud(currentEmail);
  }, [fetchClients, fetchClientCloud, currentEmail]);

  // Compute live findings from cloud simulation
  const simulatedFindings = useMemo(() => auditCloud(cloud), [cloud]);

  // If an imported dataset is active, prioritize its findings; otherwise use simulated findings
  const activeFindings = useMemo(() => {
    if (importedDataset) {
      return importedDataset.findings;
    }
    return simulatedFindings;
  }, [importedDataset, simulatedFindings]);

  // Compute score, grade, compliance
  const score = useMemo(() => {
    if (importedDataset?.rawSummary?.score !== undefined) {
      return importedDataset.rawSummary.score;
    }
    return calculateSecurityScore(activeFindings);
  }, [importedDataset, activeFindings]);

  const grade = useMemo(() => {
    if (importedDataset?.rawSummary?.grade) {
      return importedDataset.rawSummary.grade;
    }
    return calculateGrade(score);
  }, [importedDataset, score]);

  const compliance = useMemo(() => {
    if (
      importedDataset?.rawSummary?.compliance?.cis !== undefined &&
      importedDataset?.rawSummary?.compliance?.nist !== undefined
    ) {
      return {
        cis: importedDataset.rawSummary.compliance.cis,
        nist: importedDataset.rawSummary.compliance.nist
      };
    }
    return getComplianceSummary(activeFindings);
  }, [importedDataset, activeFindings]);

  // Initial encryption of summary on mount & state updates
  const encryptSummaryData = useCallback(
    async (
      currentFindings: Finding[],
      currentScore: number,
      currentGrade: string,
      currentCompliance: typeof compliance,
      isDemo: boolean,
      demoFileName?: string
    ) => {
      const summaryObject = {
        title: isDemo
          ? `Executive Cloud Security Audit (${demoFileName || 'Demo File'})`
          : `Executive Cloud Configuration Security Audit (${currentEmail})`,
        timestamp: new Date().toISOString(),
        score: currentScore,
        grade: currentGrade,
        findingsCount: currentFindings.length,
        compliance: currentCompliance,
        clientEmail: currentEmail,
        isDemoDataset: isDemo,
        sourceFileName: demoFileName || 'Live SQLite AWS Infrastructure Model',
        severities: {
          CRITICAL: currentFindings.filter((f) => f.severity === 'CRITICAL').length,
          HIGH: currentFindings.filter((f) => f.severity === 'HIGH').length,
          MEDIUM: currentFindings.filter((f) => f.severity === 'MEDIUM').length,
          LOW: currentFindings.filter((f) => f.severity === 'LOW').length
        },
        executiveStatement:
          currentScore < 40
            ? 'CRITICAL RISK DETECTED: The audited cloud environment has severe perimeter security, unencrypted data, and administrative misconfigurations. Immediate remediation is required.'
            : 'MODERATE RISK: Cloud posture is partially hardened. Safe automated mitigations have been deployed; human review is required for remaining IAM and storage snapshot controls.',
        topFindings: currentFindings.slice(0, 5).map((f) => ({
          rule_id: f.rule_id,
          severity: f.severity,
          resource: f.resource,
          issue: f.description,
          remediation: f.remediation
        }))
      };

      try {
        const payload = await encryptAuditSummary(summaryObject, 'c10ud-gU4rd-2026-s3cur3');
        setEncryptedPayload(payload);
      } catch (err) {
        console.error('Failed to encrypt summary on audit:', err);
      }
    },
    [currentEmail]
  );

  useEffect(() => {
    encryptSummaryData(
      activeFindings,
      score,
      grade,
      compliance,
      importedDataset !== null,
      importedDataset?.fileName
    );
  }, [activeFindings, score, grade, compliance, importedDataset, encryptSummaryData]);

  // Run audit and record into backend database
  const handleRunAudit = async () => {
    setIsAuditing(true);
    setIsAuditModalOpen(true);
    try {
      const res = await fetch(`/api/audit/${encodeURIComponent(currentEmail)}`, {
        method: 'POST'
      });
      if (!res.ok) {
        throw new Error(`Audit request failed (${res.status}).`);
      }
      const data = await res.json();
      if (data.success) {
        setApiError(null);
        await fetchClients();
        await fetchClientCloud(currentEmail);
      } else {
        throw new Error(data.error || 'Audit request returned an invalid response.');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to run the audit.';
      setApiError(message);
      console.error('Audit run API failed:', err);
    } finally {
      setIsAuditing(false);
      encryptSummaryData(
        activeFindings,
        score,
        grade,
        compliance,
        importedDataset !== null,
        importedDataset?.fileName
      );
    }
  };

  const handleSelectClient = (email: string) => {
    setCurrentEmail(email);
    fetchClientCloud(email);
  };

  const handleImportSuccess = (dataset: ImportedAuditDataset) => {
    setImportedDataset(dataset);
    if (dataset.hasResources && dataset.resources) {
      setCloud(dataset.resources);
    }
    setActiveTab('summary');
    setImportNotice({
      visible: true,
      fileName: dataset.fileName,
      findingsCount: dataset.findings.length,
      sourceType: dataset.sourceType.toUpperCase(),
      time: new Date().toLocaleTimeString()
    });
    // Launch audit analysis verification modal
    setIsAuditModalOpen(true);
    // Smooth scroll to top of viewport
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleResetToSimulatedCloud = () => {
    setImportedDataset(null);
    setImportNotice(null);
    fetchClientCloud(currentEmail);
  };

  // Severity metrics for charts
  const severityBreakdown = useMemo(
    () => ({
      CRITICAL: activeFindings.filter((f) => f.severity === 'CRITICAL').length,
      HIGH: activeFindings.filter((f) => f.severity === 'HIGH').length,
      MEDIUM: activeFindings.filter((f) => f.severity === 'MEDIUM').length,
      LOW: activeFindings.filter((f) => f.severity === 'LOW').length
    }),
    [activeFindings]
  );

  // Service metrics for charts
  const serviceBreakdown = useMemo(() => {
    const counts: Record<string, number> = {
      S3: 0,
      EC2: 0,
      EBS: 0,
      IAM: 0,
      RDS: 0,
      CloudTrail: 0,
      KMS: 0
    };
    activeFindings.forEach((f) => {
      if (counts[f.service] !== undefined) {
        counts[f.service]++;
      } else {
        counts[f.service] = 1;
      }
    });
    return counts;
  }, [activeFindings]);

  const isDemoActive = importedDataset !== null;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans">
      {/* Top Bar Navigation */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        score={score}
        grade={grade}
        findingsCount={activeFindings.length}
        onRunAudit={handleRunAudit}
        isAuditing={isAuditing}
        hasEncryptedPayload={encryptedPayload !== null}
        onOpenImportModal={() => setIsImportModalOpen(true)}
        isDemoDatasetActive={isDemoActive}
        importedFileName={importedDataset?.fileName}
      />

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Prominent Client Email & Database Selector Bar */}
        <ClientEmailSelector
          clients={clients}
          currentEmail={currentEmail}
          onSelectClient={handleSelectClient}
          onRefreshClients={fetchClients}
          isLoading={isLoadingClients}
        />

        {/* Import Notice Banner */}
        {apiError && (
          <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-sm text-rose-800 flex items-center justify-between gap-3">
            <span><strong>Backend error:</strong> {apiError}</span>
            <button onClick={() => setApiError(null)} className="font-semibold hover:text-rose-950" aria-label="Dismiss backend error">
              Dismiss
            </button>
          </div>
        )}

        {importNotice?.visible && (
          <div className="p-4 bg-emerald-500/15 border-2 border-emerald-500 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-3 text-slate-900 shadow-sm">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-emerald-600 text-white flex items-center justify-center font-bold text-lg shrink-0 shadow-sm">
                <CheckCircle2 className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-extrabold uppercase tracking-wider text-emerald-950">
                    Audit Data Successfully Imported & Analyzed
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-200 text-emerald-950 font-bold uppercase">
                    {importNotice.sourceType}
                  </span>
                  <span className="text-[10px] font-mono text-emerald-800">
                    {importNotice.time}
                  </span>
                </div>
                <p className="text-xs text-slate-700 mt-0.5">
                  Loaded <strong className="font-mono">{importNotice.fileName}</strong> with <strong>{importNotice.findingsCount} security findings</strong>. Posture scoring and compliance mappings have been recomputed.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={() => setIsAuditModalOpen(true)}
                className="px-3 py-1.5 text-xs font-semibold bg-emerald-700 hover:bg-emerald-800 text-white rounded-lg transition-colors flex items-center gap-1.5 shadow-2xs"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>View Scan Results</span>
              </button>
              <button
                onClick={() => setActiveTab('rules')}
                className="px-3 py-1.5 text-xs font-semibold bg-white hover:bg-slate-100 border border-slate-300 text-slate-800 rounded-lg transition-colors flex items-center gap-1.5 shadow-2xs"
              >
                <span>Findings Matrix &rarr;</span>
              </button>
              <button
                onClick={() => setImportNotice(null)}
                className="p-1.5 text-slate-500 hover:text-slate-800 rounded-lg"
                title="Dismiss"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Demo Data Banner when imported dataset is active */}
        {isDemoActive && (
          <div className="p-4 bg-amber-500/15 border-2 border-amber-500/80 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4 text-slate-900 shadow-xs">
            <div className="flex items-start md:items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-amber-500 text-slate-950 flex items-center justify-center font-bold text-xs shrink-0 font-mono">
                DEMO
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-extrabold uppercase tracking-wider text-amber-950">
                    DEMO DATA — SIMULATED, NOT A LIVE AWS SCAN
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-200 text-amber-900 font-bold uppercase">
                    {importedDataset.sourceType} import
                  </span>
                </div>
                <p className="text-xs text-slate-700 mt-0.5">
                  Active dataset: <strong className="font-mono">{importedDataset.fileName}</strong> ({activeFindings.length} findings
                  {importedDataset.hasResources ? ', 7 cloud services modeled' : ', findings matrix only'}).
                  Environment: <span className="font-mono font-semibold">{importedDataset.environment?.region || 'us-east-1'} ({importedDataset.environment?.simulation_engine || 'synthetic demonstration dataset'})</span>.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={() => setIsImportModalOpen(true)}
                className="px-3 py-1.5 text-xs font-semibold bg-white hover:bg-slate-100 border border-slate-300 rounded-lg transition-colors text-slate-800 flex items-center gap-1.5 shadow-2xs"
              >
                <UploadCloud className="w-3.5 h-3.5 text-slate-600" />
                Change File
              </button>
              <button
                onClick={handleResetToSimulatedCloud}
                className="px-3 py-1.5 text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-white rounded-lg transition-colors flex items-center gap-1.5 shadow-2xs"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                Reset to Live Simulated Cloud
              </button>
            </div>
          </div>
        )}

        {/* Tab 1: Executive Overview & Encrypted Vault */}
        {activeTab === 'summary' && (
          <div className="space-y-8">
            {/* Top Metrics Hero Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-1">
                <div className="flex items-center justify-between text-slate-500 text-xs">
                  <span className="font-semibold uppercase tracking-wider">Security Score</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-100 font-mono text-slate-700">
                    Grade {grade}
                  </span>
                </div>
                <div className="text-3xl font-extrabold font-mono text-slate-900">
                  {score} <span className="text-sm font-normal text-slate-400">/ 100</span>
                </div>
                <div className="text-[11px] text-slate-500 flex items-center justify-between pt-1">
                  <span>Deductions: -{100 - score} pts</span>
                  <button
                    onClick={() => setActiveTab('scoring')}
                    className="text-slate-700 hover:text-slate-950 font-semibold underline text-[11px]"
                  >
                    View Formula &rarr;
                  </button>
                </div>
              </div>

              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-1">
                <div className="flex items-center justify-between text-slate-500 text-xs">
                  <span className="font-semibold uppercase tracking-wider">Total Findings</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-rose-50 text-rose-700 font-mono font-semibold">
                    {severityBreakdown.CRITICAL} Critical
                  </span>
                </div>
                <div className="text-3xl font-extrabold font-mono text-slate-900">{activeFindings.length}</div>
                <div className="text-[11px] text-slate-500 flex items-center justify-between pt-1">
                  <span>{severityBreakdown.HIGH} High · {severityBreakdown.MEDIUM} Med · {severityBreakdown.LOW} Low</span>
                  <button
                    onClick={() => setActiveTab('rules')}
                    className="text-slate-700 hover:text-slate-950 font-semibold underline text-[11px]"
                  >
                    Filter &rarr;
                  </button>
                </div>
              </div>

              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-1">
                <div className="flex items-center justify-between text-slate-500 text-xs">
                  <span className="font-semibold uppercase tracking-wider">CIS Benchmark</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-100 font-mono text-slate-700">
                    12 Controls
                  </span>
                </div>
                <div className="text-3xl font-extrabold font-mono text-slate-900">{compliance.cis}%</div>
                <div className="text-[11px] text-slate-500 flex items-center justify-between pt-1">
                  <span>CIS Foundations v1.4</span>
                  <button
                    onClick={() => setActiveTab('compliance')}
                    className="text-slate-700 hover:text-slate-950 font-semibold underline text-[11px]"
                  >
                    Matrix &rarr;
                  </button>
                </div>
              </div>

              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-1">
                <div className="flex items-center justify-between text-slate-500 text-xs">
                  <span className="font-semibold uppercase tracking-wider">NIST SP 800-53</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-100 font-mono text-slate-700">
                    10 Controls
                  </span>
                </div>
                <div className="text-3xl font-extrabold font-mono text-slate-900">{compliance.nist}%</div>
                <div className="text-[11px] text-slate-500 flex items-center justify-between pt-1">
                  <span>NIST Rev. 5 Controls</span>
                  <button
                    onClick={() => setActiveTab('compliance')}
                    className="text-slate-700 hover:text-slate-950 font-semibold underline text-[11px]"
                  >
                    Matrix &rarr;
                  </button>
                </div>
              </div>
            </div>

            {/* ACTIVE DISCOVERED FINDINGS LIVE MATRIX */}
            <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-rose-600" />
                  <div>
                    <h3 className="text-sm font-bold text-slate-900">
                      Discovered Cloud Security Violations ({activeFindings.length})
                    </h3>
                    <p className="text-xs text-slate-500">
                      Live audit results across 7 AWS services against CIS Foundations v1.4 & NIST SP 800-53
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <div className="flex bg-slate-100 p-0.5 rounded-lg text-xs font-semibold">
                    {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => (
                      <button
                        key={sev}
                        onClick={() => setSummaryFindingFilter(sev)}
                        className={`px-2.5 py-1 rounded-md text-[11px] transition-colors ${
                          summaryFindingFilter === sev
                            ? 'bg-white text-slate-900 shadow-2xs font-bold'
                            : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        {sev}
                        {sev === 'ALL'
                          ? ` (${activeFindings.length})`
                          : ` (${activeFindings.filter((f) => f.severity === sev).length})`}
                      </button>
                    ))}
                  </div>

                  <button
                    onClick={() => setActiveTab('rules')}
                    className="text-xs font-bold text-slate-900 hover:text-black px-3 py-1.5 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors flex items-center gap-1 shrink-0"
                  >
                    <span>Full Table</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Table of findings */}
              <div className="overflow-x-auto border border-slate-100 rounded-lg">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900 text-white text-[11px] uppercase font-semibold">
                    <tr>
                      <th className="py-2.5 px-3">Rule ID</th>
                      <th className="py-2.5 px-3 text-center">Severity</th>
                      <th className="py-2.5 px-3">Service</th>
                      <th className="py-2.5 px-3">Affected Resource</th>
                      <th className="py-2.5 px-3">Problem Description</th>
                      <th className="py-2.5 px-3 text-center">Framework</th>
                      <th className="py-2.5 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {activeFindings
                      .filter(
                        (f) => summaryFindingFilter === 'ALL' || f.severity === summaryFindingFilter
                      )
                      .slice(0, 10)
                      .map((f, i) => (
                        <tr key={i} className="hover:bg-slate-50 transition-colors">
                          <td className="py-2.5 px-3 font-mono font-bold text-slate-900">{f.rule_id}</td>
                          <td className="py-2.5 px-3 text-center">
                            <span
                              className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                                f.severity === 'CRITICAL'
                                  ? 'bg-rose-100 text-rose-800'
                                  : f.severity === 'HIGH'
                                  ? 'bg-orange-100 text-orange-800'
                                  : f.severity === 'MEDIUM'
                                  ? 'bg-yellow-100 text-yellow-800'
                                  : 'bg-blue-100 text-blue-800'
                              }`}
                            >
                              {f.severity}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 font-semibold text-slate-700">{f.service}</td>
                          <td className="py-2.5 px-3 font-mono text-slate-600 truncate max-w-[140px]">
                            {f.resource}
                          </td>
                          <td className="py-2.5 px-3 text-slate-800 font-medium">{f.description}</td>
                          <td className="py-2.5 px-3 text-center font-mono text-[11px] text-slate-500">
                            CIS {f.cis} · NIST {f.nist}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <button
                              onClick={() => setActiveTab('resolver')}
                              className="text-[11px] font-semibold text-slate-700 hover:text-slate-950 px-2 py-1 bg-slate-100 hover:bg-slate-200 rounded transition-colors inline-flex items-center gap-1"
                            >
                              <span>Fix</span>
                              <ArrowRight className="w-3 h-3" />
                            </button>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>

              {activeFindings.length > 10 && summaryFindingFilter === 'ALL' && (
                <div className="text-center pt-1">
                  <button
                    onClick={() => setActiveTab('rules')}
                    className="text-xs text-slate-700 hover:text-slate-950 font-bold underline"
                  >
                    Showing top 10 violations. View all {activeFindings.length} findings in Module 3 Rule Engine &rarr;
                  </button>
                </div>
              )}
            </div>

            {/* THE ENCRYPTED SUMMARY VAULT */}
            <EncryptedSummaryVault
              findings={activeFindings}
              score={score}
              grade={grade}
              compliance={compliance}
              encryptedPayload={encryptedPayload}
              onUpdatePayload={setEncryptedPayload}
            />

            {/* LIVE MISCONFIGURATION RESOLVER & EXPLOIT PROBE */}
            <MisconfigurationResolver
              currentEmail={currentEmail}
              findings={activeFindings}
              onAuditUpdated={() => fetchClientCloud(currentEmail)}
            />

            {/* Visual Analytics / Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Severity Bar Chart */}
              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-slate-700" />
                    <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide">
                      Findings by Severity (severity.png)
                    </h3>
                  </div>
                  <span className="text-xs font-mono text-slate-500">{activeFindings.length} total</span>
                </div>

                <div className="space-y-3 pt-1">
                  {[
                    { label: 'CRITICAL', count: severityBreakdown.CRITICAL, color: 'bg-rose-600', text: 'text-rose-600' },
                    { label: 'HIGH', count: severityBreakdown.HIGH, color: 'bg-orange-500', text: 'text-orange-600' },
                    { label: 'MEDIUM', count: severityBreakdown.MEDIUM, color: 'bg-yellow-500', text: 'text-yellow-600' },
                    { label: 'LOW', count: severityBreakdown.LOW, color: 'bg-blue-600', text: 'text-blue-600' }
                  ].map((row) => (
                    <div key={row.label} className="space-y-1">
                      <div className="flex justify-between text-xs font-mono">
                        <span className="font-semibold text-slate-700">{row.label}</span>
                        <span className={`font-bold ${row.text}`}>{row.count}</span>
                      </div>
                      <div className="w-full bg-slate-100 h-2.5 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${row.color} transition-all duration-300 rounded-full`}
                          style={{ width: `${Math.min(100, (row.count / Math.max(1, activeFindings.length)) * 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Services Bar Chart */}
              <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-slate-700" />
                    <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide">
                      Findings by Cloud Service (services.png)
                    </h3>
                  </div>
                  <span className="text-xs font-mono text-slate-500">
                    {Object.keys(serviceBreakdown).length} Cloud Services
                  </span>
                </div>

                <div className="space-y-2.5 pt-1">
                  {Object.entries(serviceBreakdown).map(([service, count]) => (
                    <div key={service} className="space-y-1">
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-slate-700 font-medium">{service}</span>
                        <span className="font-bold text-slate-900">{count}</span>
                      </div>
                      <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-slate-700 transition-all duration-300 rounded-full"
                          style={{ width: `${Math.min(100, (count / Math.max(1, activeFindings.length)) * 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Quick Navigation Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div
                onClick={() => setActiveTab('resolver')}
                className="p-4 bg-white border border-slate-200 hover:border-slate-400 rounded-xl transition-all cursor-pointer shadow-sm group"
              >
                <div className="flex items-center justify-between text-slate-800 mb-2">
                  <span className="text-xs font-mono font-bold text-slate-500">INVESTIGATE</span>
                  <Terminal className="w-4 h-4 text-slate-400 group-hover:text-slate-900 transition-colors" />
                </div>
                <h4 className="text-sm font-bold text-slate-900">Flaw Deep-Dive & Fix</h4>
                <p className="text-xs text-slate-500 mt-1">
                  Explore attack scenarios, run Red Team exploit probes, and copy AWS CLI/Terraform code.
                </p>
              </div>

              <div
                onClick={() => setActiveTab('simulation')}
                className="p-4 bg-white border border-slate-200 hover:border-slate-400 rounded-xl transition-all cursor-pointer shadow-sm group"
              >
                <div className="flex items-center justify-between text-slate-800 mb-2">
                  <span className="text-xs font-mono font-bold text-slate-500">MODULE 1</span>
                  <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-slate-900 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                </div>
                <h4 className="text-sm font-bold text-slate-900">Simulated AWS Cloud</h4>
                <p className="text-xs text-slate-500 mt-1">
                  Explore S3, EC2, IAM, RDS, CloudTrail, KMS resources and flip configurations on/off.
                </p>
              </div>

              <div
                onClick={() => setActiveTab('remediation')}
                className="p-4 bg-white border border-slate-200 hover:border-slate-400 rounded-xl transition-all cursor-pointer shadow-sm group"
              >
                <div className="flex items-center justify-between text-slate-800 mb-2">
                  <span className="text-xs font-mono font-bold text-slate-500">SELF-HEALING</span>
                  <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-slate-900 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                </div>
                <h4 className="text-sm font-bold text-slate-900">Auto-Remediation Engine</h4>
                <p className="text-xs text-slate-500 mt-1">
                  Fix safe problems automatically, escalate risky IAM tasks, and view before/after score boost.
                </p>
              </div>

              <div
                onClick={() => setActiveTab('export')}
                className="p-4 bg-white border border-slate-200 hover:border-slate-400 rounded-xl transition-all cursor-pointer shadow-sm group"
              >
                <div className="flex items-center justify-between text-slate-800 mb-2">
                  <span className="text-xs font-mono font-bold text-slate-500">ARTIFACTS</span>
                  <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-slate-900 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                </div>
                <h4 className="text-sm font-bold text-slate-900">Export Reports & CLI</h4>
                <p className="text-xs text-slate-500 mt-1">
                  Download HTML executive reports, CSV matrices, JSON payloads, or encrypted bundles.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Flaw Investigator & Resolution Engine */}
        {activeTab === 'resolver' && (
          <MisconfigurationResolver
            currentEmail={currentEmail}
            findings={activeFindings}
            onAuditUpdated={() => fetchClientCloud(currentEmail)}
          />
        )}

        {/* Tab 3: Module 1 - Simulated Cloud */}
        {activeTab === 'simulation' && (
          <Module1Simulation
            cloud={cloud}
            onUpdateCloud={setCloud}
            isDemoDatasetActive={isDemoActive}
            importedFileName={importedDataset?.fileName}
            hasImportedResources={importedDataset ? importedDataset.hasResources : true}
            onOpenImportModal={() => setIsImportModalOpen(true)}
            onResetToDefault={handleResetToSimulatedCloud}
          />
        )}

        {/* Tab 4: Module 2 - Collectors */}
        {activeTab === 'collectors' && (
          <Module2Collectors
            cloud={cloud}
            isDemoDatasetActive={isDemoActive}
            importedFileName={importedDataset?.fileName}
            hasImportedResources={importedDataset ? importedDataset.hasResources : true}
          />
        )}

        {/* Tab 5: Module 3 - Rule Engine */}
        {activeTab === 'rules' && (
          <Module3RuleEngine
            findings={activeFindings}
            isDemoDatasetActive={isDemoActive}
            importedFileName={importedDataset?.fileName}
            onSelectRule={(ruleId) => setActiveTab('resolver')}
          />
        )}

        {/* Tab 6: Module 4 - Compliance */}
        {activeTab === 'compliance' && (
          <Module4Compliance
            findings={activeFindings}
            isDemoDatasetActive={isDemoActive}
            importedFileName={importedDataset?.fileName}
          />
        )}

        {/* Tab 7: Module 5 - Scoring & Accuracy */}
        {activeTab === 'scoring' && (
          <Module5Scoring
            findings={activeFindings}
            isDemoDatasetActive={isDemoActive}
            importedFileName={importedDataset?.fileName}
            demoAccuracy={importedDataset?.rawSummary?.accuracy}
          />
        )}

        {/* Tab 8: Auto-Remediation */}
        {activeTab === 'remediation' && (
          <AutoRemediationPanel
            cloud={cloud}
            onUpdateCloud={setCloud}
            findings={activeFindings}
            isDemoDatasetActive={isDemoActive}
            importedFileName={importedDataset?.fileName}
            onResetToDefault={handleResetToSimulatedCloud}
          />
        )}

        {/* Tab 9: Export Reports */}
        {activeTab === 'export' && (
          <ReportExportView
            findings={activeFindings}
            score={score}
            grade={grade}
            compliance={compliance}
            encryptedPayload={encryptedPayload}
          />
        )}
      </main>

      {/* Import Modal */}
      <ImportAuditModal
        isOpen={isImportModalOpen}
        onClose={() => setIsImportModalOpen(false)}
        onImportSuccess={handleImportSuccess}
        onResetToDefault={handleResetToSimulatedCloud}
        isCurrentlyImported={isDemoActive}
        activeFileName={importedDataset?.fileName}
      />

      {/* Audit Execution Modal */}
      <AuditExecutionModal
        isOpen={isAuditModalOpen}
        onClose={() => setIsAuditModalOpen(false)}
        isScanning={isAuditing}
        clientEmail={currentEmail}
        accountId={clients.find((c) => c.email === currentEmail)?.account_id || '714305265226'}
        findings={activeFindings}
        score={score}
        grade={grade}
        compliance={compliance}
        onNavigateTab={(tab) => {
          setActiveTab(tab);
          setIsAuditModalOpen(false);
        }}
        isDemoDataset={isDemoActive}
        datasetFileName={importedDataset?.fileName}
      />


      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-6 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-700">Shashank Prajapati · CloudGuard Auditor</span>
            <span>·</span>
            <span>Modules 1–5 + SQLite Knowledge Base + Exploit Simulator</span>
          </div>
          <div className="flex items-center gap-4">
            <span>CIS AWS Foundations v1.4</span>
            <span>·</span>
            <span>NIST SP 800-53 Rev. 5</span>
            <span>·</span>
            <span className="font-mono">AES-256-GCM / PBKDF2</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
