import { useState, useRef, DragEvent, ChangeEvent } from 'react';
import {
  UploadCloud,
  FileCode,
  AlertCircle,
  CheckCircle2,
  X,
  RotateCcw,
  Download,
  Shield,
  FileSpreadsheet,
  AlertTriangle,
  Layers,
  Building2,
  ExternalLink,
  Copy,
  Check,
  Zap,
  ClipboardPaste,
  FileText,
  Loader2
} from 'lucide-react';
import { ImportedAuditDataset } from '../types/security';
import {
  parseAndValidateJson,
  parseAndValidateCsv,
  ValidationResult
} from '../modules/dataImporter';
import { downloadFile } from '../modules/reporter';
import { CURATED_DEMO_DATASETS, DemoDatasetItem } from '../data/sampleDatasets';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onImportSuccess: (dataset: ImportedAuditDataset) => void;
  onResetToDefault: () => void;
  isCurrentlyImported: boolean;
  activeFileName?: string;
}

export function ImportAuditModal({
  isOpen,
  onClose,
  onImportSuccess,
  onResetToDefault,
  isCurrentlyImported,
  activeFileName
}: Props) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileContent, setFileContent] = useState<string>('');
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'samples' | 'upload' | 'paste' | 'preview'>('samples');
  const [previewDataset, setPreviewDataset] = useState<DemoDatasetItem>(CURATED_DEMO_DATASETS[0]);
  const [copiedDatasetId, setCopiedDatasetId] = useState<string | null>(null);
  const [rawPastedText, setRawPastedText] = useState<string>('');
  const [pasteFormat, setPasteFormat] = useState<'json' | 'csv'>('json');
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const showNotice = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(null), 3000);
  };

  const handleProcessContent = (content: string, fileName: string) => {
    setFileContent(content);
    const isCsv = fileName.toLowerCase().endsWith('.csv');
    const isJson = fileName.toLowerCase().endsWith('.json');

    if (!isCsv && !isJson) {
      setValidationResult({
        isValid: false,
        errors: [`Unsupported file extension for '${fileName}'. Supported file types are .json or .csv.`],
        warnings: []
      });
      return;
    }

    if (isCsv) {
      const result = parseAndValidateCsv(content, fileName);
      setValidationResult(result);
    } else {
      const result = parseAndValidateJson(content, fileName);
      setValidationResult(result);
    }
  };

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setSelectedFile(file);
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      handleProcessContent(text, file.name);
    };
    reader.onerror = () => {
      setValidationResult({
        isValid: false,
        errors: ['Failed to read file from disk. Please check file permissions.'],
        warnings: []
      });
    };
    reader.readAsText(file);
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    setSelectedFile(file);
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      handleProcessContent(text, file.name);
    };
    reader.readAsText(file);
  };

  /**
   * Primary action when user clicks "Import & Analyze Dataset" in upload tab
   */
  const handleApplyImport = () => {
    if (!selectedFile && !fileContent) {
      // Trigger file selector if nothing loaded yet
      fileInputRef.current?.click();
      showNotice('Please select or drag a .json or .csv audit file first.');
      return;
    }

    if (!validationResult) {
      showNotice('Validating audit file content...');
      return;
    }

    if (!validationResult.isValid || !validationResult.dataset) {
      showNotice('Cannot import: please resolve the validation errors listed below.');
      return;
    }

    setIsProcessing(true);
    setTimeout(() => {
      setIsProcessing(false);
      onImportSuccess(validationResult.dataset!);
      onClose();
    }, 200);
  };

  /**
   * 1-Click "Load & Analyze Now" for Enterprise Sample Datasets
   * Directly parses, validates, applies import, and launches analysis!
   */
  const handleQuickImportAndAnalyze = (item: DemoDatasetItem) => {
    setIsProcessing(true);
    const result =
      item.type === 'csv'
        ? parseAndValidateCsv(item.content, item.fileName)
        : parseAndValidateJson(item.content, item.fileName);

    if (result.isValid && result.dataset) {
      setTimeout(() => {
        setIsProcessing(false);
        onImportSuccess(result.dataset!);
        onClose();
      }, 200);
    } else {
      setIsProcessing(false);
      setSelectedFile(new File([item.content], item.fileName, { type: item.type === 'json' ? 'application/json' : 'text/csv' }));
      setFileContent(item.content);
      setValidationResult(result);
      setActiveTab('upload');
      showNotice('Validation alert on sample dataset. Opened in validator.');
    }
  };

  /**
   * Handle Direct Raw Text Paste
   */
  const handleProcessPastedText = () => {
    if (!rawPastedText.trim()) {
      showNotice('Paste box is empty. Paste raw JSON or CSV text to validate.');
      return;
    }

    const fileName = pasteFormat === 'csv' ? 'pasted_audit_findings.csv' : 'pasted_audit_data.json';
    const mime = pasteFormat === 'csv' ? 'text/csv' : 'application/json';
    const file = new File([rawPastedText], fileName, { type: mime });
    setSelectedFile(file);
    handleProcessContent(rawPastedText, fileName);
    setActiveTab('upload');
    showNotice(`Parsed pasted ${pasteFormat.toUpperCase()} content. Review validation below.`);
  };

  const handleDownloadDataset = (item: DemoDatasetItem, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const mime = item.type === 'json' ? 'application/json' : 'text/csv';
    downloadFile(item.content, item.fileName, mime);
    showNotice(`Downloaded ${item.fileName} to your downloads folder.`);
  };

  const handleCopyDataset = (item: DemoDatasetItem, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    navigator.clipboard.writeText(item.content);
    setCopiedDatasetId(item.id);
    setTimeout(() => setCopiedDatasetId(null), 2000);
  };

  const handleReset = () => {
    setSelectedFile(null);
    setFileContent('');
    setValidationResult(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
    onResetToDefault();
    onClose();
  };

  const handleClearSelected = () => {
    setSelectedFile(null);
    setFileContent('');
    setValidationResult(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-white border border-slate-200 rounded-2xl max-w-3xl w-full shadow-2xl overflow-hidden flex flex-col my-auto max-h-[92vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-900 text-white">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-slate-800 flex items-center justify-center text-emerald-400 border border-slate-700">
              <UploadCloud className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white">Import Audit Data & Enterprise Benchmarks</h3>
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  Instant Analysis Engine
                </span>
              </div>
              <p className="text-xs text-slate-400">
                1-Click load real demonstration datasets or import local custom JSON/CSV files
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Safety Disclaimer Banner */}
        <div className="px-6 py-2.5 bg-amber-50 border-b border-amber-200 text-amber-900 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-amber-600 shrink-0" />
            <span>
              <strong>Safe Offline Analysis:</strong> Parsed safely in local memory. Does not connect to live AWS credentials.
            </span>
          </div>
          {actionNotice && (
            <span className="font-mono text-[11px] font-bold text-amber-800 bg-amber-200/70 px-2 py-0.5 rounded animate-pulse">
              {actionNotice}
            </span>
          )}
        </div>

        {/* Navigation Tabs */}
        <div className="px-6 pt-3 pb-2 bg-slate-50 border-b border-slate-200">
          <div className="flex bg-slate-200/80 p-1 rounded-xl text-xs font-semibold gap-1">
            <button
              onClick={() => setActiveTab('samples')}
              className={`flex-1 py-2 px-3 rounded-lg transition-all flex items-center justify-center gap-1.5 ${
                activeTab === 'samples'
                  ? 'bg-white text-slate-900 shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Zap className="w-4 h-4 text-amber-500" />
              <span>Enterprise Samples ({CURATED_DEMO_DATASETS.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('upload')}
              className={`flex-1 py-2 px-3 rounded-lg transition-all flex items-center justify-center gap-1.5 ${
                activeTab === 'upload'
                  ? 'bg-white text-slate-900 shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <UploadCloud className="w-4 h-4 text-emerald-600" />
              <span>Upload / Drag File</span>
              {selectedFile && (
                <span className="w-2 h-2 rounded-full bg-emerald-500 ml-1"></span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('paste')}
              className={`flex-1 py-2 px-3 rounded-lg transition-all flex items-center justify-center gap-1.5 ${
                activeTab === 'paste'
                  ? 'bg-white text-slate-900 shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <ClipboardPaste className="w-4 h-4 text-indigo-600" />
              <span>Paste JSON/CSV</span>
            </button>

            <button
              onClick={() => setActiveTab('preview')}
              className={`flex-1 py-2 px-3 rounded-lg transition-all flex items-center justify-center gap-1.5 ${
                activeTab === 'preview'
                  ? 'bg-white text-slate-900 shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <FileCode className="w-4 h-4 text-slate-600" />
              <span>Inspect Code</span>
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-5 overflow-y-auto flex-1">
          {/* TAB 1: CURATED DEMO DATASETS (1-CLICK EXECUTION) */}
          {activeTab === 'samples' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700">
                    Ready-To-Use Enterprise Security Audit Datasets
                  </h4>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Click <strong className="text-emerald-700">"⚡ Load & Analyze Now"</strong> on any dataset to immediately run the audit engine!
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                {CURATED_DEMO_DATASETS.map((item) => (
                  <div
                    key={item.id}
                    className="p-4 bg-slate-50/90 hover:bg-slate-50 border border-slate-200 rounded-xl space-y-3 flex flex-col justify-between transition-all hover:border-slate-300 hover:shadow-sm"
                  >
                    <div>
                      {/* Top Badges */}
                      <div className="flex items-center justify-between gap-2 mb-2">
                        <div className="flex items-center gap-2">
                          {item.type === 'json' ? (
                            <FileCode className="w-4 h-4 text-indigo-600 shrink-0" />
                          ) : (
                            <FileSpreadsheet className="w-4 h-4 text-emerald-600 shrink-0" />
                          )}
                          <span className="font-mono text-xs font-bold text-slate-900">
                            {item.fileName}
                          </span>
                        </div>
                        <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-slate-200 text-slate-700">
                          {item.findingsCount} Findings
                        </span>
                      </div>

                      <div className="text-xs font-bold text-slate-900">
                        {item.name}
                      </div>

                      <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                        {item.environment}
                      </div>

                      <p className="text-[11px] text-slate-600 mt-2 line-clamp-2 leading-relaxed">
                        {item.summaryText}
                      </p>

                      {/* Tags */}
                      <div className="flex flex-wrap gap-1.5 mt-2.5">
                        {item.tags.map((t, idx) => (
                          <span
                            key={idx}
                            className="text-[10px] px-2 py-0.5 bg-white border border-slate-200 text-slate-700 rounded-md font-medium"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2 pt-2 border-t border-slate-200/80">
                      <button
                        onClick={() => handleQuickImportAndAnalyze(item)}
                        disabled={isProcessing}
                        className="flex-1 py-2 px-3 bg-slate-900 hover:bg-slate-800 disabled:opacity-50 text-white rounded-lg text-xs font-bold transition-all flex items-center justify-center gap-1.5 shadow-sm active:scale-[0.98]"
                      >
                        {isProcessing ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Zap className="w-3.5 h-3.5 text-amber-400 fill-amber-400" />
                        )}
                        <span>Load & Analyze Now</span>
                      </button>

                      <button
                        onClick={(e) => handleDownloadDataset(item, e)}
                        className="py-2 px-2.5 bg-white border border-slate-300 hover:bg-slate-100 text-slate-700 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1"
                        title={`Download ${item.fileName} to test manual file upload`}
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span className="hidden sm:inline">Save</span>
                      </button>

                      <button
                        onClick={() => {
                          setPreviewDataset(item);
                          setActiveTab('preview');
                        }}
                        className="p-2 bg-white border border-slate-300 hover:bg-slate-100 text-slate-600 rounded-lg text-xs transition-colors"
                        title="View raw dataset code"
                      >
                        <FileCode className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 2: UPLOAD LOCAL FILE */}
          {activeTab === 'upload' && (
            <div className="space-y-4">
              {/* Drag & Drop Box */}
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
                  isDragging
                    ? 'border-emerald-500 bg-emerald-50/50'
                    : selectedFile
                    ? 'border-emerald-400 bg-emerald-50/20'
                    : 'border-slate-300 hover:border-slate-400 bg-slate-50/30'
                }`}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  accept=".json,.csv,application/json,text/csv"
                  className="hidden"
                />

                <div className="w-12 h-12 rounded-xl bg-white border border-slate-200 mx-auto flex items-center justify-center text-slate-700 shadow-sm mb-3">
                  <UploadCloud className="w-6 h-6 text-slate-600" />
                </div>

                <div className="text-sm font-bold text-slate-800">
                  {selectedFile ? selectedFile.name : 'Choose a file or drag and drop it here'}
                </div>
                <p className="text-xs text-slate-500 mt-1">
                  Accepts <span className="font-mono font-semibold text-slate-700">.json</span> (resources + findings) or <span className="font-mono font-semibold text-slate-700">.csv</span> (findings matrix)
                </p>

                {selectedFile && (
                  <div className="mt-3 inline-flex items-center gap-2 px-3 py-1 bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-700 shadow-2xs">
                    <span>{(selectedFile.size / 1024).toFixed(1)} KB</span>
                    <span>·</span>
                    <span className="uppercase text-slate-500">{selectedFile.name.split('.').pop()}</span>
                    <span>·</span>
                    <span className="text-emerald-600 font-semibold flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" /> Ready for Import
                    </span>
                  </div>
                )}
              </div>

              {/* Quick load shortcuts */}
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
                <div className="flex items-center justify-between text-xs text-slate-600">
                  <span className="font-semibold text-slate-700">Or Click Any Demo Benchmark to Test:</span>
                  <span className="text-[11px] text-slate-500">Instant validation in memory</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {CURATED_DEMO_DATASETS.map((item) => (
                    <button
                      key={item.id}
                      onClick={() => handleQuickImportAndAnalyze(item)}
                      className="text-xs px-2.5 py-1.5 bg-white hover:bg-slate-100 border border-slate-300 rounded-lg text-slate-800 font-medium flex items-center gap-1.5 transition-colors shadow-2xs"
                    >
                      <Zap className="w-3 h-3 text-amber-500" />
                      <span>{item.fileName}</span>
                      <span className="text-[10px] text-slate-500">({item.findingsCount})</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: PASTE RAW JSON/CSV */}
          {activeTab === 'paste' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-slate-700">Select Format:</span>
                  <button
                    onClick={() => setPasteFormat('json')}
                    className={`px-2.5 py-1 text-xs font-semibold rounded-md border ${
                      pasteFormat === 'json'
                        ? 'bg-slate-900 text-white border-slate-900'
                        : 'bg-white text-slate-700 border-slate-300'
                    }`}
                  >
                    JSON
                  </button>
                  <button
                    onClick={() => setPasteFormat('csv')}
                    className={`px-2.5 py-1 text-xs font-semibold rounded-md border ${
                      pasteFormat === 'csv'
                        ? 'bg-slate-900 text-white border-slate-900'
                        : 'bg-white text-slate-700 border-slate-300'
                    }`}
                  >
                    CSV
                  </button>
                </div>
                <button
                  onClick={handleProcessPastedText}
                  className="px-3 py-1.5 text-xs font-bold bg-slate-900 text-white rounded-lg hover:bg-slate-800 transition-colors flex items-center gap-1.5"
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Parse & Validate Text</span>
                </button>
              </div>

              <textarea
                value={rawPastedText}
                onChange={(e) => setRawPastedText(e.target.value)}
                placeholder={
                  pasteFormat === 'json'
                    ? 'Paste complete JSON audit document here (e.g., {"findings": [...], "resources": {...}})...'
                    : 'Paste CSV text here:\nrule_id,severity,service,resource,description,cis,nist,remediation\nS3-001,CRITICAL,S3,prod-bucket,"Public read ACL enabled",2.1.5,AC-3,"Enforce block public access"'
                }
                rows={10}
                className="w-full p-3 font-mono text-xs bg-slate-950 text-emerald-300 rounded-xl border border-slate-300 focus:outline-none focus:ring-2 focus:ring-slate-900"
              />
            </div>
          )}

          {/* TAB 4: CODE PREVIEW */}
          {activeTab === 'preview' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <select
                    value={previewDataset.id}
                    onChange={(e) => {
                      const found = CURATED_DEMO_DATASETS.find((d) => d.id === e.target.value);
                      if (found) setPreviewDataset(found);
                    }}
                    className="text-xs font-bold font-mono bg-slate-100 border border-slate-300 rounded-lg px-2.5 py-1 text-slate-800"
                  >
                    {CURATED_DEMO_DATASETS.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.fileName} ({d.industry})
                      </option>
                    ))}
                  </select>
                  <span className="text-xs text-slate-500">
                    {previewDataset.type.toUpperCase()} · {previewDataset.findingsCount} findings
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopyDataset(previewDataset)}
                    className="text-xs px-2.5 py-1 bg-slate-100 hover:bg-slate-200 border border-slate-300 text-slate-700 rounded-lg flex items-center gap-1 font-semibold transition-colors"
                  >
                    {copiedDatasetId === previewDataset.id ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                        <span className="text-emerald-700">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-slate-500" />
                        <span>Copy Code</span>
                      </>
                    )}
                  </button>

                  <button
                    onClick={() => handleDownloadDataset(previewDataset)}
                    className="text-xs px-2.5 py-1 bg-white hover:bg-slate-100 border border-slate-300 text-slate-800 rounded-lg flex items-center gap-1 font-semibold transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download</span>
                  </button>

                  <button
                    onClick={() => handleQuickImportAndAnalyze(previewDataset)}
                    className="text-xs px-3 py-1 bg-slate-900 hover:bg-slate-800 text-white rounded-lg flex items-center gap-1.5 font-bold transition-colors shadow-sm"
                  >
                    <Zap className="w-3.5 h-3.5 text-amber-400 fill-amber-400" />
                    <span>Analyze This Dataset</span>
                  </button>
                </div>
              </div>

              <div className="relative rounded-xl border border-slate-300 overflow-hidden bg-slate-950">
                <pre className="p-4 text-[11px] font-mono text-emerald-300 max-h-[340px] overflow-y-auto leading-relaxed whitespace-pre">
                  {previewDataset.content}
                </pre>
              </div>
            </div>
          )}

          {/* Validation Feedback & Preview */}
          {validationResult && (
            <div className="space-y-3 pt-1">
              {validationResult.isValid && validationResult.dataset ? (
                <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-xl text-xs space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 font-bold text-emerald-950 text-sm">
                      <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                      <span>File Validated & Ready for Posture Analysis</span>
                    </div>
                    <span className="text-[10px] font-mono font-bold bg-emerald-200 text-emerald-900 px-2 py-0.5 rounded">
                      VALID
                    </span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 font-mono text-emerald-900">
                    <div className="bg-white/80 p-2 rounded border border-emerald-200">
                      <span className="text-[10px] text-emerald-700 uppercase block font-sans">Findings Count</span>
                      <span className="font-bold text-sm">{validationResult.dataset.findings.length} Violations</span>
                    </div>
                    <div className="bg-white/80 p-2 rounded border border-emerald-200">
                      <span className="text-[10px] text-emerald-700 uppercase block font-sans">Resources</span>
                      <span className="font-bold text-sm">{validationResult.dataset.hasResources ? 'Full Topology' : 'Findings Only'}</span>
                    </div>
                    <div className="bg-white/80 p-2 rounded border border-emerald-200">
                      <span className="text-[10px] text-emerald-700 uppercase block font-sans">Format</span>
                      <span className="font-bold text-sm uppercase">{validationResult.dataset.sourceType}</span>
                    </div>
                    <div className="bg-white/80 p-2 rounded border border-emerald-200">
                      <span className="text-[10px] text-emerald-700 uppercase block font-sans">Target Environment</span>
                      <span className="font-bold text-xs truncate block">{validationResult.dataset.environment?.region || 'Simulated'}</span>
                    </div>
                  </div>

                  {validationResult.warnings.length > 0 && (
                    <div className="text-[11px] text-amber-800 pt-1 flex items-start gap-1">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-amber-600 mt-0.5" />
                      <span>{validationResult.warnings.join(' ')}</span>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl text-xs space-y-2">
                  <div className="flex items-center gap-2 font-bold text-rose-950 text-sm">
                    <AlertCircle className="w-4 h-4 text-rose-600" />
                    <span>Validation Errors Found in File</span>
                  </div>
                  <ul className="list-disc list-inside space-y-1 text-rose-900 text-[11px] font-mono">
                    {validationResult.errors.map((err, i) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Currently Imported Banner Info */}
          {isCurrentlyImported && (
            <div className="p-3 bg-slate-100 rounded-lg text-xs text-slate-700 flex items-center justify-between">
              <span>Active dataset in workspace: <strong className="font-mono">{activeFileName}</strong></span>
              <button
                onClick={handleReset}
                className="text-slate-900 font-bold underline hover:text-black"
              >
                Reset to Default Live Cloud
              </button>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <div>
            {selectedFile && (
              <button
                onClick={handleClearSelected}
                className="text-xs text-slate-500 hover:text-slate-800 font-semibold underline"
              >
                Clear Selected File
              </button>
            )}
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-200 rounded-lg transition-colors"
            >
              Cancel
            </button>

            {isCurrentlyImported && (
              <button
                onClick={handleReset}
                className="px-3 py-2 text-xs font-semibold text-rose-700 bg-rose-50 hover:bg-rose-100 border border-rose-200 rounded-lg flex items-center gap-1.5 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                Reset to Live DB
              </button>
            )}

            <button
              onClick={handleApplyImport}
              disabled={isProcessing}
              className={`px-5 py-2.5 text-xs font-bold rounded-lg transition-all shadow-sm flex items-center gap-1.5 ${
                validationResult?.isValid
                  ? 'bg-emerald-600 hover:bg-emerald-700 text-white cursor-pointer active:scale-98 ring-2 ring-emerald-500/20'
                  : selectedFile
                  ? 'bg-slate-800 hover:bg-slate-700 text-white cursor-pointer'
                  : 'bg-slate-900 hover:bg-slate-800 text-white cursor-pointer'
              }`}
            >
              {isProcessing ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Analyzing & Importing...</span>
                </>
              ) : validationResult?.isValid ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-emerald-200" />
                  <span>Import & Analyze ({validationResult.dataset?.findings.length} Findings)</span>
                </>
              ) : selectedFile ? (
                <>
                  <UploadCloud className="w-4 h-4" />
                  <span>Validate & Import File</span>
                </>
              ) : (
                <>
                  <UploadCloud className="w-4 h-4" />
                  <span>Choose File to Import & Analyze</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
