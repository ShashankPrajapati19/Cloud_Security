import { useState } from 'react';
import { Lock, Unlock, ShieldCheck, Key, Copy, Check, Download, AlertTriangle, RefreshCw } from 'lucide-react';
import { EncryptedSummaryPayload, Finding, ComplianceSummary } from '../types/security';
import { encryptAuditSummary, decryptAuditSummary, generateStrongPassphrase } from '../modules/crypto';
import { downloadFile } from '../modules/reporter';

interface Props {
  findings: Finding[];
  score: number;
  grade: string;
  compliance: ComplianceSummary;
  encryptedPayload: EncryptedSummaryPayload | null;
  onUpdatePayload: (payload: EncryptedSummaryPayload) => void;
}

export function EncryptedSummaryVault({
  findings,
  score,
  grade,
  compliance,
  encryptedPayload,
  onUpdatePayload
}: Props) {
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [passphrase, setPassphrase] = useState('c10ud-gU4rd-2026-s3cur3');
  const [inputPassphrase, setInputPassphrase] = useState('');
  const [decryptionError, setDecryptionError] = useState<string | null>(null);
  const [copiedCiphertext, setCopiedCiphertext] = useState(false);
  const [copiedPassphrase, setCopiedPassphrase] = useState(false);
  const [activeTab, setActiveTab] = useState<'vault' | 'crypto_details'>('vault');
  const [tamperedNotice, setTamperedNotice] = useState<string | null>(null);

  // Decrypted contents state
  const [decryptedData, setDecryptedData] = useState<Record<string, unknown> | null>(null);

  const severities = {
    CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
    HIGH: findings.filter((f) => f.severity === 'HIGH').length,
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
    LOW: findings.filter((f) => f.severity === 'LOW').length
  };

  const handleEncryptNow = async (customPass?: string) => {
    const keyToUse = customPass || passphrase;
    const summaryObject = {
      title: 'Cloud Configuration Security Audit Executive Briefing',
      timestamp: new Date().toISOString(),
      score,
      grade,
      findingsCount: findings.length,
      compliance,
      severities,
      executiveStatement:
        score < 40
          ? 'CRITICAL RISK DETECTED: The simulated cloud environment has severe perimeter security, unencrypted data, and administrative misconfigurations. Immediate remediation is required.'
          : 'MODERATE RISK: Cloud posture is partially hardened. Safe automated mitigations have been deployed; human review is required for remaining IAM and storage snapshot controls.',
      topFindings: findings.slice(0, 5).map((f) => ({
        rule_id: f.rule_id,
        severity: f.severity,
        resource: f.resource,
        issue: f.description,
        remediation: f.remediation
      })),
      complianceBreakdown: {
        cisVersion: 'CIS AWS Foundations Benchmark v1.4',
        cisCompliance: `${compliance.cis}%`,
        nistVersion: 'NIST SP 800-53 Rev. 5',
        nistCompliance: `${compliance.nist}%`
      }
    };

    const newPayload = await encryptAuditSummary(summaryObject, keyToUse);
    onUpdatePayload(newPayload);
    setIsUnlocked(false);
    setDecryptedData(null);
    setDecryptionError(null);
    setTamperedNotice(null);
  };

  const handleUnlock = async () => {
    if (!encryptedPayload) return;
    setDecryptionError(null);
    try {
      const data = await decryptAuditSummary(encryptedPayload, inputPassphrase);
      setDecryptedData(data);
      setIsUnlocked(true);
      setInputPassphrase('');
    } catch (err: unknown) {
      setDecryptionError(err instanceof Error ? err.message : 'Invalid passphrase or corrupted ciphertext');
    }
  };

  const handleLockAgain = () => {
    setIsUnlocked(false);
    setDecryptedData(null);
    setDecryptionError(null);
  };

  const handleCopyCiphertext = () => {
    if (!encryptedPayload) return;
    navigator.clipboard.writeText(encryptedPayload.ciphertextBase64);
    setCopiedCiphertext(true);
    setTimeout(() => setCopiedCiphertext(false), 2000);
  };

  const handleCopyPassphrase = () => {
    navigator.clipboard.writeText(passphrase);
    setCopiedPassphrase(true);
    setTimeout(() => setCopiedPassphrase(false), 2000);
  };

  const handleGenerateNewPassphrase = () => {
    const fresh = generateStrongPassphrase();
    setPassphrase(fresh);
    handleEncryptNow(fresh);
  };

  const handleSimulateTampering = () => {
    if (!encryptedPayload) return;
    // Mutate one character of the base64 ciphertext
    const raw = encryptedPayload.ciphertextBase64;
    const modified = raw.substring(0, 10) + (raw[10] === 'A' ? 'B' : 'A') + raw.substring(11);
    const tamperedPayload: EncryptedSummaryPayload = {
      ...encryptedPayload,
      ciphertextBase64: modified
    };
    onUpdatePayload(tamperedPayload);
    setIsUnlocked(false);
    setDecryptedData(null);
    setTamperedNotice('Ciphertext was intentionally modified by 1 bit to test AES-256-GCM authentication tag verification.');
  };

  const handleDownloadEncryptedBundle = () => {
    if (!encryptedPayload) return;
    downloadFile(
      JSON.stringify(encryptedPayload, null, 2),
      `cloudguard-audit-summary-encrypted.aes.json`,
      'application/json'
    );
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
      {/* Vault Header Bar */}
      <div className="p-5 border-b border-slate-200 bg-slate-900 text-white flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-amber-400">
            {isUnlocked ? <Unlock className="w-5 h-5 text-emerald-400" /> : <Lock className="w-5 h-5" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-semibold text-white">Cryptographic Executive Summary Vault</h2>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                AES-256-GCM · PBKDF2
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Confidential audit rating, compliance percentages, and executive risk briefing are encrypted at rest.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <div className="flex bg-slate-800 rounded-lg p-1 border border-slate-700">
            <button
              onClick={() => setActiveTab('vault')}
              className={`px-3 py-1 text-xs font-medium rounded transition-colors ${
                activeTab === 'vault' ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Vault Status
            </button>
            <button
              onClick={() => setActiveTab('crypto_details')}
              className={`px-3 py-1 text-xs font-medium rounded transition-colors ${
                activeTab === 'crypto_details' ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Cipher Parameters
            </button>
          </div>

          {encryptedPayload && (
            <button
              onClick={handleDownloadEncryptedBundle}
              className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1.5 transition-colors"
              title="Download encrypted AES package"
            >
              <Download className="w-3.5 h-3.5" />
              Download .enc.json
            </button>
          )}
        </div>
      </div>

      {tamperedNotice && (
        <div className="px-5 py-3 bg-amber-50 border-b border-amber-200 text-amber-900 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
            <span>{tamperedNotice}</span>
          </div>
          <button
            onClick={() => handleEncryptNow()}
            className="text-xs font-semibold text-amber-800 underline hover:text-amber-950 ml-4"
          >
            Re-encrypt Cleanly
          </button>
        </div>
      )}

      {activeTab === 'vault' ? (
        <div className="p-6">
          {!isUnlocked ? (
            /* LOCKED STATE */
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              {/* Left Column: Locked Ciphertext Preview */}
              <div className="lg:col-span-7 space-y-4">
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-slate-300 font-mono text-xs">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-3">
                    <span className="text-slate-400 text-[11px] uppercase tracking-wider flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5 text-amber-400" />
                      Encrypted Summary Ciphertext (Base64)
                    </span>
                    <button
                      onClick={handleCopyCiphertext}
                      className="text-slate-400 hover:text-white transition-colors flex items-center gap-1 text-[11px]"
                    >
                      {copiedCiphertext ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      {copiedCiphertext ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="break-all text-emerald-400 select-all font-mono leading-relaxed h-28 overflow-y-auto pr-2">
                    {encryptedPayload ? encryptedPayload.ciphertextBase64 : 'Encrypting summary...'}
                  </div>
                  <div className="mt-3 pt-2 border-t border-slate-800 text-[11px] text-slate-500 flex justify-between">
                    <span>Algorithm: AES-256-GCM</span>
                    <span>IV: {encryptedPayload?.ivHex.substring(0, 16)}...</span>
                  </div>
                </div>

                {/* Non-sensitive high-level score indicator */}
                <div className="p-4 bg-slate-50 rounded-lg border border-slate-200">
                  <div className="text-xs font-semibold text-slate-700 uppercase tracking-wider mb-2">
                    Unencrypted Enveloping Metadata
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                    <div>
                      <span className="text-slate-500 block">Overall Score</span>
                      <span className="font-bold text-slate-900 text-base font-mono">
                        {score} / 100 <span className="text-xs font-normal text-slate-500">({grade})</span>
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Total Findings</span>
                      <span className="font-bold text-slate-900 text-base font-mono">{findings.length}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">CIS Passed</span>
                      <span className="font-bold text-slate-900 text-base font-mono">{compliance.cis}%</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">NIST Passed</span>
                      <span className="font-bold text-slate-900 text-base font-mono">{compliance.nist}%</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Right Column: Unlock Control */}
              <div className="lg:col-span-5 bg-slate-50 p-5 rounded-xl border border-slate-200 space-y-4">
                <div>
                  <h3 className="text-sm font-bold text-slate-900 flex items-center gap-1.5">
                    <Key className="w-4 h-4 text-slate-700" />
                    Unlock Executive Summary
                  </h3>
                  <p className="text-xs text-slate-600 mt-1">
                    Enter the authorized security passphrase to decrypt the executive findings briefing and risk narrative.
                  </p>
                </div>

                <div className="space-y-2">
                  <label className="block text-xs font-medium text-slate-700">Decryption Passphrase</label>
                  <div className="flex gap-2">
                    <input
                      type="password"
                      value={inputPassphrase}
                      onChange={(e) => setInputPassphrase(e.target.value)}
                      placeholder="Enter passphrase..."
                      className="w-full text-xs px-3 py-2 bg-white border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-slate-900 focus:border-transparent font-mono"
                      onKeyDown={(e) => e.key === 'Enter' && handleUnlock()}
                    />
                    <button
                      onClick={handleUnlock}
                      className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold whitespace-nowrap transition-colors"
                    >
                      Decrypt
                    </button>
                  </div>

                  {decryptionError && (
                    <p className="text-xs text-rose-600 font-medium flex items-center gap-1 mt-1">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                      {decryptionError}
                    </p>
                  )}
                </div>

                <div className="pt-3 border-t border-slate-200">
                  <div className="flex items-center justify-between text-xs text-slate-500 mb-1.5">
                    <span>Active Audit Passphrase:</span>
                    <button
                      onClick={handleCopyPassphrase}
                      className="text-slate-600 hover:text-slate-900 font-medium flex items-center gap-1 text-[11px]"
                    >
                      {copiedPassphrase ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                      {copiedPassphrase ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="p-2 bg-white border border-slate-200 rounded font-mono text-xs text-slate-800 break-all select-all">
                    {passphrase}
                  </div>
                  <div className="flex items-center justify-between mt-3 text-xs">
                    <button
                      onClick={() => setInputPassphrase(passphrase)}
                      className="text-slate-700 hover:text-slate-950 font-semibold underline text-[11px]"
                    >
                      Autofill active passphrase
                    </button>
                    <button
                      onClick={handleGenerateNewPassphrase}
                      className="text-slate-600 hover:text-slate-900 text-[11px] flex items-center gap-1"
                    >
                      <RefreshCw className="w-3 h-3" />
                      New Passphrase
                    </button>
                  </div>
                </div>

                <div className="p-3 bg-amber-50/70 border border-amber-200/80 rounded-lg text-[11px] text-amber-800 space-y-1">
                  <div className="font-semibold flex items-center gap-1">
                    <ShieldCheck className="w-3.5 h-3.5 text-amber-700" />
                    AES-GCM Authenticated Encryption
                  </div>
                  <p>
                    Attempts to tamper with or alter the encrypted payload will cause authentication tag failure during decryption.
                  </p>
                  <button
                    onClick={handleSimulateTampering}
                    className="text-amber-900 font-semibold underline hover:text-amber-950 block mt-1"
                  >
                    Simulate Ciphertext Tampering Test
                  </button>
                </div>
              </div>
            </div>
          ) : (
            /* UNLOCKED & DECRYPTED STATE */
            <div className="space-y-6">
              <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-emerald-100 flex items-center justify-center text-emerald-700 shrink-0">
                    <Unlock className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-emerald-950">Executive Summary Decrypted & Verified</h3>
                    <p className="text-xs text-emerald-700">
                      AES-256-GCM authentication tag and SHA-256 integrity hash matched.
                    </p>
                  </div>
                </div>
                <button
                  onClick={handleLockAgain}
                  className="px-3.5 py-1.5 text-xs font-semibold bg-emerald-700 hover:bg-emerald-800 text-white rounded-lg transition-colors flex items-center gap-1.5 shrink-0"
                >
                  <Lock className="w-3.5 h-3.5" />
                  Re-lock Vault
                </button>
              </div>

              {/* Decrypted Executive Content */}
              <div className="space-y-4">
                <div className="border border-slate-200 rounded-lg p-5 bg-slate-50/50">
                  <h4 className="text-sm font-bold text-slate-900 uppercase tracking-wide text-xs text-slate-500 mb-1">
                    Executive Risk Statement
                  </h4>
                  <p className="text-sm text-slate-800 leading-relaxed font-medium">
                    {String(decryptedData?.executiveStatement || '')}
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="p-4 bg-white border border-slate-200 rounded-lg">
                    <span className="text-xs text-slate-500 block mb-1">Risk Score & Grade</span>
                    <div className="text-2xl font-bold font-mono text-slate-900">
                      {score} <span className="text-base font-normal text-slate-500">/ 100</span>
                    </div>
                    <span className="text-xs font-semibold text-slate-600 mt-1 block">Grade: {grade}</span>
                  </div>

                  <div className="p-4 bg-white border border-slate-200 rounded-lg">
                    <span className="text-xs text-slate-500 block mb-1">Severities Breakdown</span>
                    <div className="flex items-center gap-2 text-xs font-mono font-semibold mt-1">
                      <span className="text-rose-600">{severities.CRITICAL} Crit</span>
                      <span>·</span>
                      <span className="text-orange-600">{severities.HIGH} High</span>
                      <span>·</span>
                      <span className="text-yellow-600">{severities.MEDIUM} Med</span>
                    </div>
                    <span className="text-xs text-slate-500 mt-1 block">{severities.LOW} Low</span>
                  </div>

                  <div className="p-4 bg-white border border-slate-200 rounded-lg">
                    <span className="text-xs text-slate-500 block mb-1">CIS Benchmark</span>
                    <div className="text-2xl font-bold font-mono text-slate-900">{compliance.cis}%</div>
                    <span className="text-xs text-slate-500 mt-1 block">CIS AWS Foundations</span>
                  </div>

                  <div className="p-4 bg-white border border-slate-200 rounded-lg">
                    <span className="text-xs text-slate-500 block mb-1">NIST SP 800-53</span>
                    <div className="text-2xl font-bold font-mono text-slate-900">{compliance.nist}%</div>
                    <span className="text-xs text-slate-500 mt-1 block">NIST Rev. 5 Controls</span>
                  </div>
                </div>

                {/* Top findings list from decrypted payload */}
                <div>
                  <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wide mb-2">
                    Priority Vulnerabilities (Decrypted Payload)
                  </h4>
                  <div className="border border-slate-200 rounded-lg overflow-hidden">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-100 border-b border-slate-200 text-slate-700 font-semibold">
                        <tr>
                          <th className="py-2.5 px-3">Rule ID</th>
                          <th className="py-2.5 px-3">Severity</th>
                          <th className="py-2.5 px-3">Resource</th>
                          <th className="py-2.5 px-3">Issue Description</th>
                          <th className="py-2.5 px-3">Remediation</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200">
                        {findings.slice(0, 5).map((f) => (
                          <tr key={f.rule_id + f.resource} className="hover:bg-slate-50">
                            <td className="py-2.5 px-3 font-mono font-semibold text-slate-900">{f.rule_id}</td>
                            <td className="py-2.5 px-3 font-semibold">
                              <span
                                className={`px-2 py-0.5 rounded text-[11px] font-mono ${
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
                            <td className="py-2.5 px-3 font-mono text-slate-700">{f.resource}</td>
                            <td className="py-2.5 px-3 text-slate-800">{f.description}</td>
                            <td className="py-2.5 px-3 text-slate-600">{f.remediation}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      ) : (
        /* CRYPTOGRAPHIC PARAMETERS DETAIL TAB */
        <div className="p-6 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 space-y-2">
              <span className="font-bold text-slate-900 block">Symmetric Cipher Suite</span>
              <div className="space-y-1 font-mono text-slate-700">
                <p>Cipher: {encryptedPayload?.algorithm || 'AES-256-GCM'}</p>
                <p>Key Length: 256 bits (32 bytes)</p>
                <p>Auth Tag Length: 128 bits (16 bytes, GCM)</p>
                <p>IV (Nonce): {encryptedPayload?.ivHex || 'N/A'} (12 bytes)</p>
              </div>
            </div>

            <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 space-y-2">
              <span className="font-bold text-slate-900 block">Key Derivation Function (KDF)</span>
              <div className="space-y-1 font-mono text-slate-700">
                <p>Function: {encryptedPayload?.kdf || 'PBKDF2-HMAC-SHA256'}</p>
                <p>Salt: {encryptedPayload?.saltHex || 'N/A'} (16 bytes)</p>
                <p>Work Factor: {encryptedPayload?.iterations.toLocaleString() || '100,000'} iterations</p>
                <p>SHA-256 Plaintext Hash: {encryptedPayload?.sha256PlaintextHash.substring(0, 16)}...</p>
              </div>
            </div>
          </div>

          <div className="p-4 bg-slate-950 text-slate-300 font-mono text-xs rounded-lg space-y-2">
            <div className="flex justify-between text-slate-400 border-b border-slate-800 pb-2">
              <span>Full Raw Cryptographic Container JSON</span>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(encryptedPayload, null, 2));
                  setCopiedCiphertext(true);
                  setTimeout(() => setCopiedCiphertext(false), 2000);
                }}
                className="hover:text-white flex items-center gap-1 text-[11px]"
              >
                {copiedCiphertext ? 'Copied Container' : 'Copy Container'}
              </button>
            </div>
            <pre className="max-h-60 overflow-y-auto text-emerald-400 select-all pr-2">
              {JSON.stringify(encryptedPayload, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
