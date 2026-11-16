import { useState } from 'react';
import { CloudSnapshot, GroundTruthItem } from '../types/security';
import { GROUND_TRUTH, getInitialCloudState, getHardenedCloudState } from '../modules/cloudSimulation';
import {
  Database,
  Folder,
  Shield,
  HardDrive,
  Users,
  Activity,
  Key,
  CheckCircle,
  AlertCircle,
  RotateCcw,
  Sparkles,
  UploadCloud,
  FileSpreadsheet
} from 'lucide-react';

interface Props {
  cloud: CloudSnapshot;
  onUpdateCloud: (updated: CloudSnapshot) => void;
  isDemoDatasetActive?: boolean;
  importedFileName?: string;
  hasImportedResources?: boolean;
  onOpenImportModal?: () => void;
  onResetToDefault?: () => void;
}

export function Module1Simulation({
  cloud,
  onUpdateCloud,
  isDemoDatasetActive = false,
  importedFileName,
  hasImportedResources = true,
  onOpenImportModal,
  onResetToDefault
}: Props) {
  const [activeCategory, setActiveCategory] = useState<'all' | 's3' | 'ec2' | 'iam' | 'rds' | 'trails' | 'kms'>('all');
  const [showGroundTruthTable, setShowGroundTruthTable] = useState(false);

  const handleResetToGroundTruth = () => {
    onUpdateCloud(getInitialCloudState());
  };

  const handleApplyHardened = () => {
    onUpdateCloud(getHardenedCloudState());
  };

  const toggleS3PublicAcl = (bucketName: string) => {
    const next = { ...cloud, s3: cloud.s3.map((b) => (b.name === bucketName ? { ...b, public_acl: !b.public_acl } : b)) };
    onUpdateCloud(next);
  };

  const toggleS3Encryption = (bucketName: string) => {
    const next = { ...cloud, s3: cloud.s3.map((b) => (b.name === bucketName ? { ...b, encrypted: !b.encrypted } : b)) };
    onUpdateCloud(next);
  };

  const toggleS3Versioning = (bucketName: string) => {
    const next = { ...cloud, s3: cloud.s3.map((b) => (b.name === bucketName ? { ...b, versioning: !b.versioning } : b)) };
    onUpdateCloud(next);
  };

  const toggleVolumeEncryption = (volId: string) => {
    const next = { ...cloud, volumes: cloud.volumes.map((v) => (v.id === volId ? { ...v, encrypted: !v.encrypted } : v)) };
    onUpdateCloud(next);
  };

  const toggleUserMfa = (userName: string) => {
    const next = { ...cloud, iam_users: cloud.iam_users.map((u) => (u.name === userName ? { ...u, mfa: !u.mfa } : u)) };
    onUpdateCloud(next);
  };

  const toggleUserAdmin = (userName: string) => {
    const next = { ...cloud, iam_users: cloud.iam_users.map((u) => (u.name === userName ? { ...u, admin: !u.admin } : u)) };
    onUpdateCloud(next);
  };

  const toggleRdsPublic = (dbId: string) => {
    const next = { ...cloud, rds: cloud.rds.map((d) => (d.id === dbId ? { ...d, publicly_accessible: !d.publicly_accessible } : d)) };
    onUpdateCloud(next);
  };

  const toggleRdsEncryption = (dbId: string) => {
    const next = { ...cloud, rds: cloud.rds.map((d) => (d.id === dbId ? { ...d, storage_encrypted: !d.storage_encrypted } : d)) };
    onUpdateCloud(next);
  };

  const toggleKmsRotation = (keyId: string) => {
    const next = { ...cloud, kms: cloud.kms.map((k) => (k.id === keyId ? { ...k, rotation: !k.rotation } : k)) };
    onUpdateCloud(next);
  };

  return (
    <div className="space-y-6">
      {/* Prominent Demo Data Banner if imported */}
      {isDemoDatasetActive && (
        <div className="p-4 bg-amber-500/15 border-2 border-amber-500/80 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-slate-900">
          <div className="flex items-start sm:items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-amber-500 text-slate-950 flex items-center justify-center font-bold text-xs shrink-0 font-mono">
              DEMO
            </div>
            <div>
              <div className="text-xs font-mono font-extrabold uppercase tracking-wider text-amber-950">
                DEMO DATA — SIMULATED, NOT A LIVE AWS SCAN
              </div>
              <p className="text-xs text-slate-700 mt-0.5">
                Active dataset loaded from <strong className="font-mono">{importedFileName || 'demo file'}</strong>. No live AWS accounts were accessed or queried.
              </p>
            </div>
          </div>
          {onResetToDefault && (
            <button
              onClick={onResetToDefault}
              className="text-xs font-bold text-slate-900 bg-white hover:bg-slate-100 border border-slate-300 px-3 py-1.5 rounded-lg shrink-0 transition-colors shadow-xs"
            >
              Reset to Live Simulated Cloud
            </button>
          )}
        </div>
      )}

      {/* Intro banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
              Module 1
            </span>
            <h2 className="text-lg font-bold text-slate-900">Simulated AWS Cloud Infrastructure</h2>
          </div>
          <p className="text-xs text-slate-600 mt-1">
            Modeled directly from moto/boto3 simulation. Contains both compliant resources and 15 intentionally planted misconfigurations.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {onOpenImportModal && (
            <button
              onClick={onOpenImportModal}
              className="px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white hover:bg-slate-100 border border-slate-300 rounded-lg flex items-center gap-1.5 transition-colors"
            >
              <UploadCloud className="w-3.5 h-3.5 text-slate-600" />
              Import Audit Data
            </button>
          )}
          <button
            onClick={() => setShowGroundTruthTable(!showGroundTruthTable)}
            className="px-3 py-1.5 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors"
          >
            {showGroundTruthTable ? 'Hide Answer Key' : 'Inspect 15 Planted Issues Key'}
          </button>
          <button
            onClick={handleResetToGroundTruth}
            className="px-3 py-1.5 text-xs font-semibold text-slate-700 border border-slate-300 hover:bg-slate-50 rounded-lg flex items-center gap-1.5 transition-colors"
            title="Reset to the 15 planted issues baseline"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset Ground Truth
          </button>
          <button
            onClick={handleApplyHardened}
            className="px-3.5 py-1.5 text-xs font-semibold bg-emerald-700 hover:bg-emerald-800 text-white rounded-lg flex items-center gap-1.5 transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Apply 100% Hardened
          </button>
        </div>
      </div>

      {/* Notice if CSV was imported without resources */}
      {!hasImportedResources && (
        <div className="p-4 bg-sky-50 border border-sky-200 rounded-xl text-xs text-sky-900 flex items-start gap-3">
          <FileSpreadsheet className="w-5 h-5 text-sky-600 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-bold">CSV Findings Mode Active</div>
            <p className="text-sky-800 leading-relaxed">
              This audit was imported from a CSV findings matrix (<code className="font-mono bg-sky-100 px-1 py-0.5 rounded">{importedFileName || 'sample_findings.csv'}</code>).
              CSV exports contain finding rows but do not include raw cloud resource dumps.
              Below are the standard simulated cloud baseline resources, or you can switch to the <strong>Rules Engine</strong> and <strong>Compliance</strong> tabs to view the imported CSV findings directly.
            </p>
          </div>
        </div>
      )}

      {/* Answer Key Modal / Collapsible */}
      {showGroundTruthTable && (
        <div className="bg-slate-900 text-white border border-slate-800 rounded-xl p-5 space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <span className="font-bold text-amber-400">Ground Truth "Answer Key"</span>
              <span className="text-slate-400">({GROUND_TRUTH.length} intentionally planted security flaws)</span>
            </div>
            <button
              onClick={() => setShowGroundTruthTable(false)}
              className="text-slate-400 hover:text-white text-xs underline"
            >
              Close
            </button>
          </div>
          <p className="text-slate-400 font-sans text-xs">
            In Module 5, the auditor's findings are evaluated against this exact answer key to measure precision and recall.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 pt-1 max-h-60 overflow-y-auto">
            {GROUND_TRUTH.map((item: GroundTruthItem, idx: number) => (
              <div key={idx} className="bg-slate-950 p-2.5 rounded border border-slate-800 flex justify-between items-center">
                <span className="text-slate-300 truncate mr-2">{item.resource}</span>
                <span className="text-amber-400 font-bold shrink-0">{item.rule_id}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Category selector */}
      <div className="flex flex-wrap items-center gap-2">
        {[
          { id: 'all', label: 'All Resources' },
          { id: 's3', label: `S3 Buckets (${cloud.s3.length})` },
          { id: 'ec2', label: `Firewalls & EBS (${cloud.sg.length + cloud.volumes.length})` },
          { id: 'iam', label: `IAM & Auth (${cloud.iam_users.length + 1})` },
          { id: 'rds', label: `RDS Databases (${cloud.rds.length})` },
          { id: 'trails', label: `CloudTrail (${cloud.trails.length})` },
          { id: 'kms', label: `KMS Keys (${cloud.kms.length})` }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveCategory(tab.id as typeof activeCategory)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              activeCategory === tab.id
                ? 'bg-slate-900 text-white'
                : 'bg-white text-slate-600 hover:text-slate-900 border border-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Grid of Cloud Services */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* S3 Buckets */}
        {(activeCategory === 'all' || activeCategory === 's3') && (
          <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
              <Folder className="w-4 h-4 text-sky-600" />
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide">
                S3 Buckets ({cloud.s3.length})
              </h3>
            </div>
            <div className="space-y-3">
              {cloud.s3.map((b) => (
                <div key={b.name} className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="font-mono font-bold text-slate-900 truncate">{b.name}</span>
                    {b.public_acl ? (
                      <span className="text-[10px] bg-rose-100 text-rose-800 font-semibold px-1.5 py-0.5 rounded">
                        PUBLIC
                      </span>
                    ) : (
                      <span className="text-[10px] bg-emerald-100 text-emerald-800 font-semibold px-1.5 py-0.5 rounded">
                        PRIVATE
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-600">
                    <div className="flex items-center justify-between">
                      <span>Public ACL:</span>
                      <button
                        onClick={() => toggleS3PublicAcl(b.name)}
                        className={`font-semibold underline ${b.public_acl ? 'text-rose-600' : 'text-emerald-700'}`}
                      >
                        {b.public_acl ? 'true (BAD)' : 'false'}
                      </button>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Encryption:</span>
                      <button
                        onClick={() => toggleS3Encryption(b.name)}
                        className={`font-semibold underline ${b.encrypted ? 'text-emerald-700' : 'text-rose-600'}`}
                      >
                        {b.encrypted ? 'AES256' : 'None (BAD)'}
                      </button>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Versioning:</span>
                      <button
                        onClick={() => toggleS3Versioning(b.name)}
                        className={`font-semibold underline ${b.versioning ? 'text-emerald-700' : 'text-amber-600'}`}
                      >
                        {b.versioning ? 'Enabled' : 'Off (BAD)'}
                      </button>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Public Block:</span>
                      <span className={`font-semibold ${b.pab ? 'text-emerald-700' : 'text-amber-600'}`}>
                        {b.pab ? 'Full' : 'Partial'}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* EC2 Security Groups */}
        {(activeCategory === 'all' || activeCategory === 'ec2') && (
          <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
              <Shield className="w-4 h-4 text-purple-600" />
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide">
                Security Groups ({cloud.sg.length})
              </h3>
            </div>
            <div className="space-y-3">
              {cloud.sg.map((sg) => (
                <div key={sg.id} className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-1.5">
                  <div className="flex justify-between items-center">
                    <span className="font-mono font-bold text-slate-900">{sg.group_name}</span>
                    <span className="text-[10px] text-slate-500 font-mono">{sg.id}</span>
                  </div>
                  <p className="text-[11px] text-slate-600">{sg.description}</p>
                  <div className="pt-1 border-t border-slate-200">
                    <span className="text-[10px] text-slate-500 uppercase font-semibold block mb-1">
                      Ingress Rules ({sg.ip_permissions.length})
                    </span>
                    {sg.ip_permissions.length === 0 ? (
                      <span className="text-[11px] text-slate-400">No inbound ingress rules (secure)</span>
                    ) : (
                      sg.ip_permissions.map((p, idx) => (
                        <div key={idx} className="flex justify-between items-center text-[11px] font-mono">
                          <span>
                            {p.protocol === '-1' ? 'ALL protocols' : `Port ${p.from_port || 'all'}`}
                          </span>
                          <span
                            className={
                              p.cidr === '0.0.0.0/0' && (p.protocol === '-1' || p.from_port === 22)
                                ? 'text-rose-600 font-bold'
                                : 'text-slate-700'
                            }
                          >
                            {p.cidr}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* EBS Volumes */}
        {(activeCategory === 'all' || activeCategory === 'ec2') && (
          <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
              <HardDrive className="w-4 h-4 text-indigo-600" />
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide">
                EBS Volumes ({cloud.volumes.length})
              </h3>
            </div>
            <div className="space-y-3">
              {cloud.volumes.map((v) => (
                <div key={v.id} className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="font-mono font-bold text-slate-900">{v.id}</span>
                    <span className="text-[11px] text-slate-500 font-mono">{v.size_gb} GB · {v.az}</span>
                  </div>
                  <div className="flex justify-between items-center pt-1 border-t border-slate-200 text-[11px]">
                    <span className="text-slate-600">Storage Encryption:</span>
                    <button
                      onClick={() => toggleVolumeEncryption(v.id)}
                      className={`font-semibold underline ${v.encrypted ? 'text-emerald-700' : 'text-amber-600'}`}
                    >
                      {v.encrypted ? 'Encrypted (GOOD)' : 'Unencrypted (BAD)'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* IAM Users & Password Policy */}
        {(activeCategory === 'all' || activeCategory === 'iam') && (
          <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
              <Users className="w-4 h-4 text-emerald-600" />
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide">
                IAM Users & Credentials
              </h3>
            </div>
            <div className="space-y-3">
              {cloud.iam_users.map((u) => (
                <div key={u.name} className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="font-mono font-bold text-slate-900">{u.name}</span>
                    {u.admin && (
                      <span className="text-[10px] bg-rose-100 text-rose-800 font-semibold px-1.5 py-0.5 rounded">
                        Full Admin (*:*)
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-600 pt-1 border-t border-slate-200">
                    <div className="flex justify-between items-center">
                      <span>MFA Enrolled:</span>
                      <button
                        onClick={() => toggleUserMfa(u.name)}
                        className={`font-semibold underline ${u.mfa ? 'text-emerald-700' : 'text-rose-600'}`}
                      >
                        {u.mfa ? 'Enabled' : 'None (BAD)'}
                      </button>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>Admin Rights:</span>
                      <button
                        onClick={() => toggleUserAdmin(u.name)}
                        className={`font-semibold underline ${u.admin ? 'text-rose-600' : 'text-slate-700'}`}
                      >
                        {u.admin ? '*:* (BAD)' : 'Restricted'}
                      </button>
                    </div>
                    <div className="col-span-2 flex justify-between items-center text-[11px]">
                      <span>Active Access Key Age:</span>
                      <span className={`font-mono font-semibold ${u.key_ages[0] > 90 ? 'text-amber-600' : 'text-slate-700'}`}>
                        {u.key_ages.length > 0 ? `${u.key_ages[0]} days (${u.key_ages[0] > 90 ? 'Old Key' : 'Fresh'})` : 'No Keys'}
                      </span>
                    </div>
                  </div>
                </div>
              ))}

              {/* Password Policy Card */}
              <div className="p-3 bg-slate-100/70 border border-slate-200 rounded-lg text-xs space-y-1">
                <span className="text-[11px] font-bold text-slate-800 uppercase block">Account Password Policy</span>
                <div className="flex justify-between text-[11px] text-slate-600">
                  <span>Minimum Length:</span>
                  <span className={`font-mono font-bold ${cloud.password_policy && cloud.password_policy.min_length >= 14 ? 'text-emerald-700' : 'text-amber-600'}`}>
                    {cloud.password_policy?.min_length || 0} chars ({cloud.password_policy && cloud.password_policy.min_length >= 14 ? 'Compliant' : 'Too Weak'})
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* RDS Databases */}
        {(activeCategory === 'all' || activeCategory === 'rds') && (
          <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
              <Database className="w-4 h-4 text-cyan-600" />
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide">
                RDS Databases ({cloud.rds.length})
              </h3>
            </div>
            <div className="space-y-3">
              {cloud.rds.map((db) => (
                <div key={db.id} className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="font-mono font-bold text-slate-900">{db.id}</span>
                    <span className="text-[11px] text-slate-500 font-mono">{db.engine}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-600 pt-1 border-t border-slate-200">
                    <div className="flex justify-between items-center">
                      <span>Public Routing:</span>
                      <button
                        onClick={() => toggleRdsPublic(db.id)}
                        className={`font-semibold underline ${db.publicly_accessible ? 'text-rose-600' : 'text-emerald-700'}`}
                      >
                        {db.publicly_accessible ? 'Public (BAD)' : 'Private'}
                      </button>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>Encryption:</span>
                      <button
                        onClick={() => toggleRdsEncryption(db.id)}
                        className={`font-semibold underline ${db.storage_encrypted ? 'text-emerald-700' : 'text-rose-600'}`}
                      >
                        {db.storage_encrypted ? 'Enabled' : 'Off (BAD)'}
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* CloudTrail & KMS */}
        {(activeCategory === 'all' || activeCategory === 'trails' || activeCategory === 'kms') && (
          <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
              <Activity className="w-4 h-4 text-rose-600" />
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide">
                CloudTrail & KMS Audit
              </h3>
            </div>
            <div className="space-y-3">
              {/* CloudTrail section */}
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-1.5">
                <span className="text-[11px] font-bold text-slate-800 uppercase block">CloudTrail Audit Diary</span>
                {cloud.trails.length === 0 ? (
                  <div className="p-2 bg-rose-50 border border-rose-200 rounded text-rose-800 text-[11px] flex items-center gap-1.5">
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                    <span>No active multi-region trails configured (CT-001)</span>
                  </div>
                ) : (
                  cloud.trails.map((t) => (
                    <div key={t.name} className="flex justify-between text-[11px] font-mono text-emerald-800">
                      <span>{t.name}</span>
                      <span>Active & Logging</span>
                    </div>
                  ))
                )}
              </div>

              {/* KMS Keys */}
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-2">
                <span className="text-[11px] font-bold text-slate-800 uppercase block">KMS Encryption Keys</span>
                {cloud.kms.map((k) => (
                  <div key={k.id} className="pt-1 border-t border-slate-200 space-y-1">
                    <div className="flex justify-between text-[11px]">
                      <span className="font-mono text-slate-700 truncate mr-2">{k.id.substring(0, 14)}...</span>
                      <button
                        onClick={() => toggleKmsRotation(k.id)}
                        className={`font-semibold underline ${k.rotation ? 'text-emerald-700' : 'text-amber-600'}`}
                      >
                        {k.rotation ? 'Rotation ON' : 'Rotation OFF (BAD)'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
