import { useState, useMemo } from 'react';
import { Finding, ControlRow, ComplianceSummary } from '../types/security';
import { buildControlTable, calculateCompliancePercent } from '../modules/compliance';
import { CheckCircle2, XCircle, ShieldCheck, FileCheck, Layers } from 'lucide-react';

interface Props {
  findings: Finding[];
  isDemoDatasetActive?: boolean;
  importedFileName?: string;
}

export function Module4Compliance({
  findings,
  isDemoDatasetActive = false,
  importedFileName
}: Props) {
  const [selectedFramework, setSelectedFramework] = useState<'cis' | 'nist'>('cis');

  const cisTable = useMemo(() => buildControlTable(findings, 'cis'), [findings]);
  const nistTable = useMemo(() => buildControlTable(findings, 'nist'), [findings]);

  const cisPercent = calculateCompliancePercent(cisTable);
  const nistPercent = calculateCompliancePercent(nistTable);

  const currentTable = selectedFramework === 'cis' ? cisTable : nistTable;
  const currentPercent = selectedFramework === 'cis' ? cisPercent : nistPercent;

  return (
    <div className="space-y-6">
      {/* Prominent Demo Data Banner if imported */}
      {isDemoDatasetActive && (
        <div className="p-4 bg-amber-500/15 border-2 border-amber-500/80 rounded-xl text-slate-900 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2.5">
            <span className="font-mono font-bold bg-amber-500 text-slate-950 px-2 py-0.5 rounded text-[10px]">
              DEMO DATA
            </span>
            <span>
              Compliance controls evaluated from demo findings in <strong className="font-mono">{importedFileName}</strong> (DEMO DATA — SIMULATED, NOT A LIVE AWS SCAN).
            </span>
          </div>
        </div>
      )}

      {/* Intro Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
              Module 4
            </span>
            <h2 className="text-lg font-bold text-slate-900">Regulatory Compliance Mapping</h2>
          </div>
          <p className="text-xs text-slate-600 mt-1 max-w-2xl">
            Groups findings under standard industry controls. A control passes if none of its assigned rules trigger a finding.
            Compliance % = (Controls Passed / Total Controls) × 100.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs">
            <span className="text-slate-500 block text-[11px] uppercase">CIS Benchmark</span>
            <span className="text-base font-bold font-mono text-slate-900">{cisPercent}%</span>
          </div>
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs">
            <span className="text-slate-500 block text-[11px] uppercase">NIST SP 800-53</span>
            <span className="text-base font-bold font-mono text-slate-900">{nistPercent}%</span>
          </div>
        </div>
      </div>

      {/* Framework Tabs */}
      <div className="flex bg-slate-100 rounded-lg p-1 border border-slate-200 w-fit">
        <button
          onClick={() => setSelectedFramework('cis')}
          className={`px-4 py-2 text-xs font-semibold rounded-md transition-colors flex items-center gap-2 ${
            selectedFramework === 'cis' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <ShieldCheck className="w-4 h-4 text-slate-700" />
          CIS AWS Foundations Benchmark ({cisPercent}%)
        </button>
        <button
          onClick={() => setSelectedFramework('nist')}
          className={`px-4 py-2 text-xs font-semibold rounded-md transition-colors flex items-center gap-2 ${
            selectedFramework === 'nist' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <Layers className="w-4 h-4 text-slate-700" />
          NIST SP 800-53 Rev. 5 ({nistPercent}%)
        </button>
      </div>

      {/* Control Matrix Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 bg-slate-50 border-b border-slate-200 flex justify-between items-center text-xs">
          <div>
            <span className="font-bold text-slate-900">
              {selectedFramework === 'cis' ? 'CIS AWS Foundations Benchmark Controls' : 'NIST SP 800-53 Security Controls'}
            </span>
            <span className="text-slate-500 ml-2">
              ({currentTable.filter((r) => r.status === 'PASS').length} of {currentTable.length} passing)
            </span>
          </div>
          <div className="font-mono text-slate-700 font-semibold">
            Compliance Score: {currentPercent}%
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900 text-white uppercase text-[11px] font-semibold tracking-wider">
              <tr>
                <th className="py-3 px-4 w-28">Control</th>
                <th className="py-3 px-4">Control Specification & Title</th>
                <th className="py-3 px-4">Associated Rule IDs</th>
                <th className="py-3 px-4 text-center w-28">Status</th>
                <th className="py-3 px-4 text-center w-36">Failing Resources</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {currentTable.map((row) => (
                <tr
                  key={row.control}
                  className={`transition-colors ${
                    row.status === 'PASS' ? 'bg-emerald-50/50 hover:bg-emerald-50/70' : 'bg-rose-50/50 hover:bg-rose-50/70'
                  }`}
                >
                  <td className="py-3 px-4 font-mono font-bold text-slate-900">{row.control}</td>
                  <td className="py-3 px-4 text-slate-800 font-medium">{row.title || 'Standard baseline control'}</td>
                  <td className="py-3 px-4 font-mono text-slate-700">{row.rules.join(', ')}</td>
                  <td className="py-3 px-4 text-center">
                    <span
                      className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded font-mono font-bold text-xs ${
                        row.status === 'PASS'
                          ? 'bg-emerald-200 text-emerald-950'
                          : 'bg-rose-200 text-rose-950'
                      }`}
                    >
                      {row.status === 'PASS' ? (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-800" />
                          PASS
                        </>
                      ) : (
                        <>
                          <XCircle className="w-3.5 h-3.5 text-rose-800" />
                          FAIL
                        </>
                      )}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-center font-mono font-bold text-slate-900">
                    {row.failing_resources}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
