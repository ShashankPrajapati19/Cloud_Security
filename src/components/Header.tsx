import { Shield, RefreshCw, Lock, UploadCloud, GraduationCap } from 'lucide-react';

interface Props {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  score: number;
  grade: string;
  findingsCount: number;
  onRunAudit: () => void;
  isAuditing: boolean;
  hasEncryptedPayload: boolean;
  onOpenImportModal: () => void;
  
  isDemoDatasetActive: boolean;
  importedFileName?: string;
}

export function Header({
  activeTab,
  setActiveTab,
  score,
  grade,
  findingsCount,
  onRunAudit,
  isAuditing,
  hasEncryptedPayload,
  onOpenImportModal,
  isDemoDatasetActive,
  importedFileName
}: Props) {
  const navItems = [
    { id: 'summary', label: 'Encrypted Vault' },
    { id: 'resolver', label: 'Inspect & Resolve' },
    { id: 'simulation', label: '1. Simulated Cloud' },
    { id: 'collectors', label: '2. Collectors' },
    { id: 'rules', label: '3. Rules Engine' },
    { id: 'compliance', label: '4. Compliance' },
    { id: 'scoring', label: '5. Scoring & Accuracy' },
    { id: 'remediation', label: 'Auto-Remediation' },
    { id: 'export', label: 'Export Reports' }
  ];

  return (
    <header className="sticky top-0 z-40 bg-white/95 backdrop-blur-md border-b border-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between gap-8 h-16">
          {/* Zone 1: Brand Wordmark (Single text element) */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-9 h-9 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-sm">
              <Shield className="w-5 h-5 text-emerald-400" />
            </div>
            <button
              onClick={() => setActiveTab('summary')}
              className="text-lg font-bold tracking-tight text-slate-900 hover:text-slate-700 transition-colors whitespace-nowrap shrink-0 text-left"
            >
              <span className="hidden sm:inline">Shashank Prajapati · </span>CloudGuard
            </button>
          </div>

          {/* Zone 2: Navigation Links (Single line, text with active states) */}
          <nav className="hidden xl:flex items-center gap-1 overflow-x-auto text-xs font-semibold text-slate-600">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`px-3 py-1.5 rounded-lg whitespace-nowrap shrink-0 transition-colors ${
                  activeTab === item.id
                    ? 'bg-slate-100 text-slate-900 font-bold'
                    : 'hover:text-slate-900 hover:bg-slate-50'
                }`}
              >
                {item.label}
              </button>
            ))}
          </nav>

          {/* Zone 3: Primary Action & Score Telemetry */}
          <div className="flex items-center gap-2.5 shrink-0">
            {isDemoDatasetActive ? (
              <div
                onClick={onOpenImportModal}
                className="cursor-pointer flex items-center gap-1.5 text-[11px] font-mono font-bold bg-amber-500 text-slate-950 px-2.5 py-1.5 rounded-lg border border-amber-600 shadow-sm"
                title={`Imported demo dataset: ${importedFileName || 'Demo File'}. Click to manage.`}
              >
                <span>DEMO DATA</span>
                <span className="hidden sm:inline font-normal text-slate-900 truncate max-w-[100px]">({importedFileName})</span>
              </div>
            ) : null}

            {/* Score pill */}
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono">
              <span className="text-slate-500">Score:</span>
              <span
                className={`font-bold ${
                  score >= 75 ? 'text-emerald-700' : score >= 50 ? 'text-amber-600' : 'text-rose-600'
                }`}
              >
                {score}/100 ({grade})
              </span>
              <span className="text-slate-300">|</span>
              <span className="text-slate-600">{findingsCount} Issues</span>
            </div>

            {hasEncryptedPayload && (
              <span
                title="Audit summary is encrypted with AES-256-GCM"
                className="hidden lg:flex items-center gap-1 text-[11px] font-mono font-semibold text-amber-700 bg-amber-50 border border-amber-200 px-2.5 py-1 rounded-lg"
              >
                <Lock className="w-3 h-3 text-amber-600" />
                Vault Locked
              </span>
            )}

            

            {/* Import Audit Data Button */}
            <button
              onClick={onOpenImportModal}
              className="px-3 py-2 text-xs font-semibold text-slate-700 bg-white hover:bg-slate-100 border border-slate-300 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 shadow-xs"
              title="Import demo audit dataset (.json or .csv)"
            >
              <UploadCloud className="w-3.5 h-3.5 text-slate-600" />
              <span className="hidden sm:inline">Import Audit Data</span>
              <span className="sm:hidden">Import</span>
            </button>

            {/* Run Audit CTA */}
            <button
              onClick={onRunAudit}
              disabled={isAuditing}
              className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-50 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 shadow-sm"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isAuditing ? 'animate-spin' : ''}`} />
              <span>{isAuditing ? 'Auditing...' : 'Run Audit'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Mobile / Tablet Horizontal Navigation Strip */}
      <div className="xl:hidden overflow-x-auto border-t border-slate-100 px-4 py-2 flex items-center gap-1 bg-slate-50/80">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`px-3 py-1 rounded-md text-xs whitespace-nowrap font-medium transition-colors ${
              activeTab === item.id
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
            }`}
          >
            {item.label}
          </button>
        ))}
      </div>
    </header>
  );
}
