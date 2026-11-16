import { useState } from 'react';
import { CloudSnapshot } from '../types/security';
import { Eye, Copy, Check, Code, FileText, CheckCircle2 } from 'lucide-react';

interface Props {
  cloud: CloudSnapshot;
  isDemoDatasetActive?: boolean;
  importedFileName?: string;
  hasImportedResources?: boolean;
}

export function Module2Collectors({
  cloud,
  isDemoDatasetActive = false,
  importedFileName,
  hasImportedResources = true
}: Props) {
  const [selectedCollector, setSelectedCollector] = useState<
    's3' | 'sg' | 'volumes' | 'iam' | 'policy' | 'rds' | 'trails' | 'kms' | 'all_json'
  >('s3');
  const [copied, setCopied] = useState(false);

  const collectorsList = [
    { id: 's3', label: 'collect_s3()', desc: 'Queries S3: list_buckets, get_bucket_acl, get_bucket_encryption, get_public_access_block, get_bucket_versioning', count: cloud.s3.length },
    { id: 'sg', label: 'collect_sg()', desc: 'Queries EC2: describe_security_groups (ip_permissions inspection)', count: cloud.sg.length },
    { id: 'volumes', label: 'collect_volumes()', desc: 'Queries EBS: describe_volumes (encrypted flag)', count: cloud.volumes.length },
    { id: 'iam', label: 'collect_iam_users()', desc: 'Queries IAM: list_users, list_attached_user_policies, list_mfa_devices, list_access_keys', count: cloud.iam_users.length },
    { id: 'policy', label: 'collect_password_policy()', desc: 'Queries IAM: get_account_password_policy (min length, symbols, age)', count: cloud.password_policy ? 1 : 0 },
    { id: 'rds', label: 'collect_rds()', desc: 'Queries RDS: describe_db_instances (PubliclyAccessible, StorageEncrypted)', count: cloud.rds.length },
    { id: 'trails', label: 'collect_trails()', desc: 'Queries CloudTrail: describe_trails, get_trail_status (IsLogging, IsMultiRegionTrail)', count: cloud.trails.length },
    { id: 'kms', label: 'collect_kms()', desc: 'Queries KMS: list_keys, describe_key, get_key_rotation_status', count: cloud.kms.length },
    { id: 'all_json', label: 'collect_all() [Unified Snapshot]', desc: 'Consolidated read-only snapshot dictionary ready for rule engine audit', count: 8 }
  ];

  const getCollectorPayload = () => {
    switch (selectedCollector) {
      case 's3':
        return cloud.s3;
      case 'sg':
        return cloud.sg;
      case 'volumes':
        return cloud.volumes;
      case 'iam':
        return cloud.iam_users;
      case 'policy':
        return cloud.password_policy;
      case 'rds':
        return cloud.rds;
      case 'trails':
        return cloud.trails;
      case 'kms':
        return cloud.kms;
      case 'all_json':
      default:
        return cloud;
    }
  };

  const currentPayloadString = JSON.stringify(getCollectorPayload(), null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(currentPayloadString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

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
              Collector query displays configurations parsed from demo file <strong className="font-mono">{importedFileName}</strong>.
            </span>
          </div>
          {!hasImportedResources && (
            <span className="text-amber-900 font-semibold text-[11px]">
              (CSV export did not include resource dumps; displaying baseline schema)
            </span>
          )}
        </div>
      )}

      {/* Intro banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
            Module 2
          </span>
          <h2 className="text-lg font-bold text-slate-900">Read-Only API Snapshot Collectors</h2>
        </div>
        <p className="text-xs text-slate-600 mt-1 max-w-3xl">
          Collectors isolate the cloud communication layer from the evaluation engine. They only issue read-only calls
          (<code className="font-mono bg-slate-100 px-1 py-0.5 rounded">list_*</code>, <code className="font-mono bg-slate-100 px-1 py-0.5 rounded">describe_*</code>, <code className="font-mono bg-slate-100 px-1 py-0.5 rounded">get_*</code>)
          and produce clean structured data. The rule engine never communicates with AWS APIs directly.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Collectors list */}
        <div className="lg:col-span-4 bg-white border border-slate-200 rounded-xl p-4 space-y-2 shadow-sm">
          <span className="text-xs font-bold text-slate-500 uppercase tracking-wider block mb-2 px-2">
            Collector Functions (8 Endpoints)
          </span>
          {collectorsList.map((col) => (
            <button
              key={col.id}
              onClick={() => setSelectedCollector(col.id as typeof selectedCollector)}
              className={`w-full text-left p-2.5 rounded-lg text-xs transition-colors flex items-start justify-between gap-2 ${
                selectedCollector === col.id
                  ? 'bg-slate-900 text-white shadow-sm'
                  : 'hover:bg-slate-50 text-slate-700 border border-transparent'
              }`}
            >
              <div>
                <span className="font-mono font-bold block">{col.label}</span>
                <span className={`text-[11px] block mt-0.5 ${selectedCollector === col.id ? 'text-slate-300' : 'text-slate-500'}`}>
                  {col.desc.substring(0, 52)}...
                </span>
              </div>
              <span
                className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded shrink-0 ${
                  selectedCollector === col.id ? 'bg-slate-800 text-slate-200' : 'bg-slate-100 text-slate-600'
                }`}
              >
                {col.count} items
              </span>
            </button>
          ))}
        </div>

        {/* Right: Collected JSON Payload Inspector */}
        <div className="lg:col-span-8 bg-slate-950 rounded-xl border border-slate-800 p-5 space-y-3 text-slate-300 font-mono text-xs shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Code className="w-4 h-4 text-emerald-400" />
              <span className="font-bold text-white text-xs">
                Collector Output: {selectedCollector === 'all_json' ? 'collect_all()' : `collect_${selectedCollector}()`}
              </span>
            </div>

            <button
              onClick={handleCopy}
              className="text-slate-400 hover:text-white transition-colors flex items-center gap-1.5 text-xs bg-slate-900 px-3 py-1.5 rounded border border-slate-800"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied to Clipboard' : 'Copy Payload'}
            </button>
          </div>

          <pre className="max-h-[500px] overflow-y-auto pr-2 text-emerald-400 leading-relaxed font-mono select-all">
            {currentPayloadString}
          </pre>

          <div className="border-t border-slate-800 pt-3 text-[11px] text-slate-400 flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              Read-only immutable snapshot
            </span>
            <span>Payload Size: {new Blob([currentPayloadString]).size} bytes</span>
          </div>
        </div>
      </div>
    </div>
  );
}
