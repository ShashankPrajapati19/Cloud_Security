import { useState } from 'react';
import { Mail, Building2, Server, Database, Plus, Check, RefreshCw, UserCheck } from 'lucide-react';

export interface ClientProfile {
  id: string;
  email: string;
  name: string;
  company: string;
  cloud_provider: string;
  account_id: string;
  region: string;
  environment: string;
  created_at: string;
  latest_audit?: {
    score: number;
    grade: string;
    findings_count: number;
    cis_compliance: number;
    nist_compliance: number;
  };
}

interface Props {
  clients: ClientProfile[];
  currentEmail: string;
  onSelectClient: (email: string) => void;
  onRefreshClients: () => void;
  isLoading: boolean;
}

export function ClientEmailSelector({
  clients,
  currentEmail,
  onSelectClient,
  onRefreshClients,
  isLoading
}: Props) {
  const [showAddModal, setShowAddModal] = useState(false);
  const [newEmail, setNewEmail] = useState('');
  const [newName, setNewName] = useState('');
  const [newCompany, setNewCompany] = useState('');
  const [newRegion, setNewRegion] = useState('us-east-1');
  const [newEnv, setNewEnv] = useState('Production AWS VPC');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const activeClient =
    clients.find((c) => c.email === currentEmail) ||
    clients[0] || {
      id: 'client_01',
      email: currentEmail || 'kakuverma385@gmail.com',
      name: 'Shashank Prajapati',
      company: 'Enterprise Security Architecture Lab',
      account_id: '714305265226',
      region: 'us-east-1',
      environment: 'Production AWS Core',
      cloud_provider: 'AWS',
      created_at: new Date().toISOString()
    };

  const handleCreateClient = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEmail || !newName) {
      setErrorMsg('Email and contact name are required.');
      return;
    }
    setIsSubmitting(true);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/clients', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: newEmail,
          name: newName,
          company: newCompany || 'Enterprise Cloud Client',
          region: newRegion,
          environment: newEnv
        })
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to create client');
      }
      onRefreshClients();
      onSelectClient(newEmail);
      setShowAddModal(false);
      setNewEmail('');
      setNewName('');
      setNewCompany('');
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        {/* Active Client Info */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-slate-900 text-emerald-400 flex items-center justify-center shrink-0 shadow-xs">
            <UserCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">
                Active Client / Database Target
              </span>
              <span className="inline-flex items-center gap-1 text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200">
                <Database className="w-3 h-3 text-emerald-600" />
                SQLite Backend Active
              </span>
            </div>
            <div className="text-sm font-bold text-slate-900 flex items-center gap-2 mt-0.5">
              <span>{activeClient?.name || 'Shashank Prajapati'}</span>
              <span className="text-xs font-normal text-slate-500 font-mono">({activeClient?.email})</span>
            </div>
          </div>
        </div>

        {/* Client Email Dropdown & Add Button */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-2">
            <Mail className="w-4 h-4 text-slate-400 shrink-0" />
            <select
              value={currentEmail}
              onChange={(e) => onSelectClient(e.target.value)}
              className="text-xs font-medium px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900 focus:bg-white"
            >
              {clients.map((c) => (
                <option key={c.email} value={c.email}>
                  {c.email} — {c.company} ({c.account_id})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={onRefreshClients}
            disabled={isLoading}
            className="p-2 text-slate-600 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors border border-slate-200"
            title="Refresh database records"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>

          <button
            onClick={() => setShowAddModal(true)}
            className="px-3 py-2 text-xs font-semibold text-slate-900 bg-emerald-50 hover:bg-emerald-100 text-emerald-900 border border-emerald-300 rounded-lg flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Plus className="w-3.5 h-3.5 text-emerald-700" />
            Add Client Email
          </button>
        </div>
      </div>

      {/* Target Cloud Specs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-100 text-xs text-slate-600">
        <div>
          <span className="text-slate-400 block text-[10px] uppercase">AWS Account ID</span>
          <span className="font-mono font-bold text-slate-800">{activeClient?.account_id || '714305265226'}</span>
        </div>
        <div>
          <span className="text-slate-400 block text-[10px] uppercase">Environment</span>
          <span className="font-semibold text-slate-800">{activeClient?.environment || 'Production Core AWS'}</span>
        </div>
        <div>
          <span className="text-slate-400 block text-[10px] uppercase">Primary Region</span>
          <span className="font-mono font-semibold text-slate-800">{activeClient?.region || 'us-east-1'}</span>
        </div>
        <div>
          <span className="text-slate-400 block text-[10px] uppercase">Company / Organization</span>
          <span className="font-semibold text-slate-800 truncate block">{activeClient?.company || 'Enterprise Lab'}</span>
        </div>
      </div>

      {/* Modal to Register New Client */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-xs p-4">
          <div className="bg-white border border-slate-200 rounded-2xl max-w-md w-full shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <h3 className="text-base font-bold text-slate-900">Register New Audit Client</h3>
                <p className="text-xs text-slate-500">Add an email and cloud environment to the SQLite database</p>
              </div>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-slate-600 text-sm font-bold"
              >
                ✕
              </button>
            </div>

            {errorMsg && (
              <div className="p-3 bg-rose-50 border border-rose-200 text-rose-800 text-xs rounded-lg">
                {errorMsg}
              </div>
            )}

            <form onSubmit={handleCreateClient} className="space-y-3 text-xs">
              <div>
                <label className="block font-semibold text-slate-700 mb-1">Client Email Address *</label>
                <input
                  type="email"
                  required
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  placeholder="e.g. security-lead@client-bank.com"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-slate-900 font-mono"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">Lead Contact Name *</label>
                <input
                  type="text"
                  required
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="e.g. Alex Thorne"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-slate-900"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">Company / Team</label>
                <input
                  type="text"
                  value={newCompany}
                  onChange={(e) => setNewCompany(e.target.value)}
                  placeholder="e.g. FinTech Global Vaults"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-slate-900"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">AWS Region</label>
                  <select
                    value={newRegion}
                    onChange={(e) => setNewRegion(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-900 focus:bg-white focus:outline-none font-mono"
                  >
                    <option value="us-east-1">us-east-1 (N. Virginia)</option>
                    <option value="us-west-2">us-west-2 (Oregon)</option>
                    <option value="eu-west-1">eu-west-1 (Ireland)</option>
                    <option value="ap-southeast-1">ap-southeast-1 (Singapore)</option>
                  </select>
                </div>
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">Environment Tag</label>
                  <input
                    type="text"
                    value={newEnv}
                    onChange={(e) => setNewEnv(e.target.value)}
                    placeholder="e.g. Production Core"
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-900 focus:bg-white focus:outline-none"
                  />
                </div>
              </div>

              <div className="pt-3 border-t border-slate-100 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 text-slate-600 hover:bg-slate-100 rounded-lg font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2 bg-slate-900 hover:bg-slate-800 disabled:opacity-50 text-white rounded-lg font-semibold"
                >
                  {isSubmitting ? 'Saving to Database...' : 'Register Client'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
