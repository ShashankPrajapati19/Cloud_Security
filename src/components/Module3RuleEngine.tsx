import { useState, useMemo } from 'react';
import { Finding, Severity, ServiceName } from '../types/security';
import { RULES_CATALOG } from '../modules/rulesCatalog';
import { Search, ShieldAlert, BookOpen, AlertOctagon, AlertTriangle, Info, Wrench } from 'lucide-react';

interface Props {
  findings: Finding[];
  isDemoDatasetActive?: boolean;
  importedFileName?: string;
  onSelectRule?: (ruleId: string) => void;
}

export function Module3RuleEngine({
  findings,
  isDemoDatasetActive = false,
  importedFileName,
  onSelectRule
}: Props) {
  const [viewMode, setViewMode] = useState<'findings' | 'catalog'>('findings');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | Severity>('ALL');
  const [serviceFilter, setServiceFilter] = useState<'ALL' | ServiceName>('ALL');

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
      if (serviceFilter !== 'ALL' && f.service !== serviceFilter) return false;
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          f.rule_id.toLowerCase().includes(query) ||
          f.resource.toLowerCase().includes(query) ||
          f.description.toLowerCase().includes(query) ||
          f.remediation.toLowerCase().includes(query) ||
          f.cis.toLowerCase().includes(query) ||
          f.nist.toLowerCase().includes(query)
        );
      }
      return true;
    });
  }, [findings, severityFilter, serviceFilter, searchQuery]);

  const allRulesList = useMemo(() => Object.values(RULES_CATALOG), []);

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
              Displaying findings loaded from demo file <strong className="font-mono">{importedFileName}</strong> (DEMO DATA — SIMULATED, NOT A LIVE AWS SCAN).
            </span>
          </div>
        </div>
      )}

      {/* Intro banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
              Module 3
            </span>
            <h2 className="text-lg font-bold text-slate-900">Rule Engine & Checklist Catalog</h2>
          </div>
          <p className="text-xs text-slate-600 mt-1">
            Evaluates collected cloud settings against 15 CIS and NIST mapped security rules. Each failure generates a structured Finding.
          </p>
        </div>

        <div className="flex bg-slate-100 rounded-lg p-1 border border-slate-200 shrink-0">
          <button
            onClick={() => setViewMode('findings')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors ${
              viewMode === 'findings' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Live Findings ({findings.length})
          </button>
          <button
            onClick={() => setViewMode('catalog')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors ${
              viewMode === 'catalog' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            15 Rules Catalog
          </button>
        </div>
      </div>

      {viewMode === 'findings' ? (
        <div className="space-y-4">
          {/* Controls bar */}
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search findings by rule, resource, CIS, NIST, or keywords..."
                className="w-full text-xs pl-9 pr-3 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-slate-900 focus:bg-white"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as typeof severityFilter)}
                className="text-xs px-2.5 py-2 bg-white border border-slate-200 rounded-lg text-slate-700 font-medium"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              <select
                value={serviceFilter}
                onChange={(e) => setServiceFilter(e.target.value as typeof serviceFilter)}
                className="text-xs px-2.5 py-2 bg-white border border-slate-200 rounded-lg text-slate-700 font-medium"
              >
                <option value="ALL">All Services</option>
                <option value="S3">S3</option>
                <option value="EC2">EC2</option>
                <option value="EBS">EBS</option>
                <option value="IAM">IAM</option>
                <option value="RDS">RDS</option>
                <option value="CloudTrail">CloudTrail</option>
                <option value="KMS">KMS</option>
              </select>
            </div>
          </div>

          {/* Findings Table */}
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900 text-white uppercase text-[11px] font-semibold tracking-wider">
                  <tr>
                    <th className="py-3 px-4">Rule</th>
                    <th className="py-3 px-4 text-center">Severity</th>
                    <th className="py-3 px-4">Service</th>
                    <th className="py-3 px-4">Affected Resource</th>
                    <th className="py-3 px-4">Problem Description</th>
                    <th className="py-3 px-4 text-center">CIS</th>
                    <th className="py-3 px-4 text-center">NIST</th>
                    <th className="py-3 px-4">Remediation Guidance</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {filteredFindings.length === 0 ? (
                    <tr>
                      <td colSpan={9} className="py-8 text-center text-slate-500 font-medium">
                        No security findings match your filter criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredFindings.map((f) => (
                      <tr
                        key={f.rule_id + f.resource}
                        className={`transition-colors ${
                          f.severity === 'CRITICAL'
                            ? 'bg-rose-50/70 hover:bg-rose-50'
                            : f.severity === 'HIGH'
                            ? 'bg-orange-50/70 hover:bg-orange-50'
                            : f.severity === 'MEDIUM'
                            ? 'bg-yellow-50/60 hover:bg-yellow-50'
                            : 'bg-sky-50/50 hover:bg-sky-50'
                        }`}
                      >
                        <td className="py-3 px-4 font-mono font-bold text-slate-900 whitespace-nowrap">
                          {f.rule_id}
                        </td>
                        <td className="py-3 px-4 text-center whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                              f.severity === 'CRITICAL'
                                ? 'bg-rose-600 text-white'
                                : f.severity === 'HIGH'
                                ? 'bg-orange-600 text-white'
                                : f.severity === 'MEDIUM'
                                ? 'bg-yellow-500 text-slate-950'
                                : 'bg-sky-600 text-white'
                            }`}
                          >
                            {f.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-semibold text-slate-700 whitespace-nowrap">{f.service}</td>
                        <td className="py-3 px-4 font-mono font-semibold text-slate-900 whitespace-nowrap">
                          {f.resource}
                        </td>
                        <td className="py-3 px-4 text-slate-800 font-medium">{f.description}</td>
                        <td className="py-3 px-4 font-mono text-center text-slate-700 font-semibold">{f.cis}</td>
                        <td className="py-3 px-4 font-mono text-center text-slate-700 font-semibold">{f.nist}</td>
                        <td className="py-3 px-4 text-slate-600">{f.remediation}</td>
                        <td className="py-3 px-4 text-right whitespace-nowrap">
                          {onSelectRule && (
                            <button
                              onClick={() => onSelectRule(f.rule_id)}
                              className="px-2.5 py-1 text-[11px] font-bold bg-slate-900 hover:bg-slate-800 text-white rounded transition-colors"
                            >
                              Investigate &rarr;
                            </button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className="p-3 bg-slate-50 border-t border-slate-200 text-[11px] text-slate-500 flex justify-between items-center">
              <span>Showing {filteredFindings.length} of {findings.length} active findings</span>
              <span>Sorted by Severity: CRITICAL &gt; HIGH &gt; MEDIUM &gt; LOW</span>
            </div>
          </div>
        </div>
      ) : (
        /* 15 Rules Catalog View */
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900 text-white uppercase text-[11px] font-semibold tracking-wider">
                <tr>
                  <th className="py-3 px-4">Rule ID</th>
                  <th className="py-3 px-4">Service</th>
                  <th className="py-3 px-4 text-center">Severity</th>
                  <th className="py-3 px-4">Rule Title</th>
                  <th className="py-3 px-4 text-center">CIS v1.4</th>
                  <th className="py-3 px-4 text-center">NIST Rev.5</th>
                  <th className="py-3 px-4">Recommended Remediation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {allRulesList.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-50">
                    <td className="py-3 px-4 font-mono font-bold text-slate-900">{r.id}</td>
                    <td className="py-3 px-4 font-semibold text-slate-700">{r.service}</td>
                    <td className="py-3 px-4 text-center">
                      <span
                        className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                          r.severity === 'CRITICAL'
                            ? 'bg-rose-100 text-rose-800'
                            : r.severity === 'HIGH'
                            ? 'bg-orange-100 text-orange-800'
                            : r.severity === 'MEDIUM'
                            ? 'bg-yellow-100 text-yellow-800'
                            : 'bg-blue-100 text-blue-800'
                        }`}
                      >
                        {r.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-800">
                      <div>{r.title}</div>
                      <div className="text-[11px] text-slate-500 mt-0.5">{r.explanation}</div>
                    </td>
                    <td className="py-3 px-4 font-mono text-center text-slate-700 font-semibold">{r.cis || '—'}</td>
                    <td className="py-3 px-4 font-mono text-center text-slate-700 font-semibold">{r.nist}</td>
                    <td className="py-3 px-4 text-slate-600">{r.remediation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
