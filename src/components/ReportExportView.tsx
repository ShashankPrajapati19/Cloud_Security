import { useState } from 'react';
import { Finding, ComplianceSummary, EncryptedSummaryPayload } from '../types/security';
import { generateHtmlReport, generateCsvReport, downloadFile } from '../modules/reporter';
import { Download, FileCode, FileSpreadsheet, Lock, Terminal, Check, Copy } from 'lucide-react';

interface Props {
  findings: Finding[];
  score: number;
  grade: string;
  compliance: ComplianceSummary;
  encryptedPayload: EncryptedSummaryPayload | null;
}

export function ReportExportView({ findings, score, grade, compliance, encryptedPayload }: Props) {
  const [copiedCli, setCopiedCli] = useState(false);

  const handleDownloadHtml = () => {
    const html = generateHtmlReport(
      findings,
      score,
      grade,
      compliance,
      encryptedPayload ? `Audit Summary Encrypted with AES-256-GCM (Checksum: ${encryptedPayload.sha256PlaintextHash.substring(0, 12)}...)` : undefined
    );
    downloadFile(html, 'cloud-security-report.html', 'text/html');
  };

  const handleDownloadCsv = () => {
    const csv = generateCsvReport(findings);
    downloadFile(csv, 'findings.csv', 'text/csv');
  };

  const handleDownloadJson = () => {
    const json = JSON.stringify(
      {
        auditTitle: 'Cloud Configuration Security Audit',
        timestamp: new Date().toISOString(),
        score,
        grade,
        compliance,
        findingsCount: findings.length,
        findings
      },
      null,
      2
    );
    downloadFile(json, 'findings.json', 'application/json');
  };

  const handleDownloadEncrypted = () => {
    if (!encryptedPayload) return;
    downloadFile(
      JSON.stringify(encryptedPayload, null, 2),
      'cloudguard-audit-summary-encrypted.aes.json',
      'application/json'
    );
  };

  const cliCode = `# From the CloudGuard project directory:
Set-Location "<project-folder>"

# Install dependencies
npm install

# Start the local audit dashboard
npm run dev

# Validate types and build for production
npm run lint
npm run build

# Backend health check
Invoke-WebRequest http://localhost:3000/api/health`;

  const handleCopyCli = () => {
    navigator.clipboard.writeText(cliCode);
    setCopiedCli(true);
    setTimeout(() => setCopiedCli(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Intro Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
        <h2 className="text-lg font-bold text-slate-900">Reports & Evidence Package Exporter</h2>
        <p className="text-xs text-slate-600 mt-1">
          Export standardized evidence packages for compliance officers, SOC2 auditors, engineering managers, and pipeline automation.
        </p>
      </div>

      {/* Export Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* HTML Report */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-10 h-10 rounded-lg bg-slate-100 flex items-center justify-center text-slate-800">
              <FileCode className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-bold text-slate-900">HTML Executive Report</h3>
            <p className="text-xs text-slate-500 leading-relaxed">
              Standalone, self-contained HTML report with white card layout, styled findings table, and severity highlights.
            </p>
          </div>
          <button
            onClick={handleDownloadHtml}
            className="w-full py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Download report.html
          </button>
        </div>

        {/* CSV Findings */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-10 h-10 rounded-lg bg-slate-100 flex items-center justify-center text-slate-800">
              <FileSpreadsheet className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-bold text-slate-900">CSV Findings Matrix</h3>
            <p className="text-xs text-slate-500 leading-relaxed">
              Standard comma-separated table format ideal for ingestion into SIEMs, Jira queues, or Excel spreadsheets.
            </p>
          </div>
          <button
            onClick={handleDownloadCsv}
            className="w-full py-2 bg-slate-100 hover:bg-slate-200 text-slate-900 border border-slate-300 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Download findings.csv
          </button>
        </div>

        {/* JSON Snapshot */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-10 h-10 rounded-lg bg-slate-100 flex items-center justify-center text-slate-800">
              <FileCode className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-bold text-slate-900">JSON Audit Payload</h3>
            <p className="text-xs text-slate-500 leading-relaxed">
              Structured machine-readable JSON containing complete findings metadata, compliance percentages, and timestamps.
            </p>
          </div>
          <button
            onClick={handleDownloadJson}
            className="w-full py-2 bg-slate-100 hover:bg-slate-200 text-slate-900 border border-slate-300 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Download findings.json
          </button>
        </div>

        {/* Encrypted Package */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-10 h-10 rounded-lg bg-amber-50 border border-amber-200 flex items-center justify-center text-amber-700">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-bold text-slate-900">Encrypted AES Package</h3>
            <p className="text-xs text-slate-500 leading-relaxed">
              AES-256-GCM encrypted executive summary vault package with PBKDF2 salt, IV, and SHA-256 integrity tag.
            </p>
          </div>
          <button
            onClick={handleDownloadEncrypted}
            disabled={!encryptedPayload}
            className="w-full py-2 bg-amber-600 hover:bg-amber-700 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Download .aes.json
          </button>
        </div>
      </div>

      {/* CLI Script Execution Card */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 text-slate-300 font-mono text-xs space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2 text-white font-bold">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span>CloudGuard Local Commands</span>
          </div>
          <button
            onClick={handleCopyCli}
            className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px] bg-slate-900 px-3 py-1.5 rounded border border-slate-800"
          >
            {copiedCli ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copiedCli ? 'Copied Command' : 'Copy Commands'}
          </button>
        </div>

        <pre className="text-emerald-400 select-all leading-relaxed font-mono overflow-x-auto py-2">
          {cliCode}
        </pre>
      </div>
    </div>
  );
}
