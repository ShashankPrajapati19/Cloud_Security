import { Finding, ComplianceSummary } from '../types/security';

export function generateHtmlReport(
  findings: Finding[],
  score: number,
  grade: string,
  compliance: ComplianceSummary,
  encryptedNotice?: string
): string {
  const rowsHtml = findings
    .map(
      (r) => `
    <tr class="${r.severity}">
      <td style="font-weight:600;font-family:monospace">${r.rule_id}</td>
      <td class="sev sev-${r.severity}">${r.severity}</td>
      <td>${r.service}</td>
      <td style="font-family:monospace">${r.resource}</td>
      <td>${r.description}</td>
      <td style="text-align:center">${r.cis}</td>
      <td style="text-align:center">${r.nist}</td>
      <td>${r.remediation}</td>
    </tr>`
    )
    .join('');

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Shashank Prajapati | Cloud Configuration Security Audit Report</title>
  <style>
    body { background:#f1f5f9; margin:0; padding:32px; font-family:'Plus Jakarta Sans', Arial, sans-serif; color:#0f172a; }
    .card { background:#ffffff; border-radius:12px; border:1px solid #e2e8f0; padding:32px; max-width:1200px; margin:0 auto; box-shadow:0 4px 6px -1px rgba(0,0,0,0.05); }
    h1 { margin:0 0 8px 0; color:#0f172a; font-size:24px; font-weight:700; }
    h2 { margin:0 0 16px 0; color:#334155; font-size:18px; font-weight:600; }
    .metrics { display:flex; gap:24px; margin-bottom:24px; flex-wrap:wrap; }
    .metric-box { background:#f8fafc; border:1px solid #e2e8f0; padding:12px 18px; border-radius:8px; }
    .metric-title { font-size:12px; color:#64748b; margin-bottom:4px; text-transform:uppercase; letter-spacing:0.05em; }
    .metric-val { font-size:20px; font-weight:700; color:#0f172a; font-family:monospace; }
    .aud-table { border-collapse:collapse; width:100%; background:#ffffff; color:#0f172a; font-size:13px; margin-top:16px; }
    .aud-table th { background:#0f172a; color:#ffffff; padding:10px 12px; text-align:left; font-size:12px; text-transform:uppercase; letter-spacing:0.05em; }
    .aud-table td { padding:10px 12px; border:1px solid #e2e8f0; color:#1e293b; }
    .aud-table tr.CRITICAL td { background:#fee2e2; }
    .aud-table tr.HIGH td { background:#ffedd5; }
    .aud-table tr.MEDIUM td { background:#fef9c3; }
    .aud-table tr.LOW td { background:#e0f2fe; }
    .aud-table td.sev { font-weight:700; text-align:center; font-size:11px; }
    .aud-table td.sev-CRITICAL { background:#dc2626; color:#ffffff; }
    .aud-table td.sev-HIGH { background:#ea580c; color:#ffffff; }
    .aud-table td.sev-MEDIUM { background:#ca8a04; color:#ffffff; }
    .aud-table td.sev-LOW { background:#0284c7; color:#ffffff; }
    .footer { margin-top:24px; font-size:12px; color:#64748b; border-top:1px solid #e2e8f0; padding-top:16px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Shashank Prajapati · Cloud Configuration Security Audit Report</h1>
    <h2>Security Score: ${score} / 100 (Grade ${grade})</h2>
    ${encryptedNotice ? `<div style="background:#eff6ff;border:1px solid #bfdbfe;color:#1e40af;padding:10px 14px;border-radius:6px;margin-bottom:20px;font-size:13px;">🔒 ${encryptedNotice}</div>` : ''}
    <div class="metrics">
      <div class="metric-box">
        <div class="metric-title">Total Findings</div>
        <div class="metric-val">${findings.length}</div>
      </div>
      <div class="metric-box">
        <div class="metric-title">CIS Benchmark Compliance</div>
        <div class="metric-val">${compliance.cis}%</div>
      </div>
      <div class="metric-box">
        <div class="metric-title">NIST 800-53 Compliance</div>
        <div class="metric-val">${compliance.nist}%</div>
      </div>
      <div class="metric-box">
        <div class="metric-title">Audit Timestamp</div>
        <div class="metric-val" style="font-size:14px">${new Date().toISOString()}</div>
      </div>
    </div>

    <table class="aud-table">
      <thead>
        <tr>
          <th>Rule</th>
          <th>Severity</th>
          <th>Service</th>
          <th>Resource</th>
          <th>Issue Description</th>
          <th>CIS</th>
          <th>NIST</th>
          <th>Remediation Guidance</th>
        </tr>
      </thead>
      <tbody>
        ${rowsHtml}
      </tbody>
    </table>

    <div class="footer">
      Generated for Shashank Prajapati by CloudGuard Security Configuration Auditor · Read-only Non-Destructive Inspection Engine
    </div>
  </div>
</body>
</html>`;
}

export function generateCsvReport(findings: Finding[]): string {
  const headers = ['rule_id', 'severity', 'service', 'resource', 'description', 'cis', 'nist', 'remediation'];
  const rows = findings.map((f) => [
    f.rule_id,
    f.severity,
    f.service,
    `"${f.resource}"`,
    `"${f.description.replace(/"/g, '""')}"`,
    f.cis,
    f.nist,
    `"${f.remediation.replace(/"/g, '""')}"`
  ]);
  return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
}

export function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
