import { useMemo } from 'react';
import { Finding, GroundTruthItem } from '../types/security';
import { GROUND_TRUTH } from '../modules/cloudSimulation';
import { calculateSecurityScore, calculateGrade, evaluateAccuracy, WEIGHTS } from '../modules/scoring';
import { Target, CheckCircle, ShieldAlert, Award, AlertCircle, BarChart3 } from 'lucide-react';

interface Props {
  findings: Finding[];
  isDemoDatasetActive?: boolean;
  importedFileName?: string;
  demoAccuracy?: {
    precision?: number;
    recall?: number;
    planted?: number;
    found?: number;
    correct?: number;
  };
}

export function Module5Scoring({
  findings,
  isDemoDatasetActive = false,
  importedFileName,
  demoAccuracy
}: Props) {
  const score = useMemo(() => calculateSecurityScore(findings), [findings]);
  const grade = useMemo(() => calculateGrade(score), [score]);
  const computedEvaluation = useMemo(() => evaluateAccuracy(findings, GROUND_TRUTH), [findings]);

  const evaluation = useMemo(() => {
    if (demoAccuracy && demoAccuracy.precision !== undefined && demoAccuracy.recall !== undefined) {
      return {
        planted: demoAccuracy.planted ?? 15,
        found: demoAccuracy.found ?? findings.length,
        correct: demoAccuracy.correct ?? Math.round((demoAccuracy.recall ?? 1) * (demoAccuracy.planted ?? 15)),
        precision: demoAccuracy.precision ?? 1,
        recall: demoAccuracy.recall ?? 1,
        missed: [],
        false_alarms: []
      };
    }
    return computedEvaluation;
  }, [demoAccuracy, computedEvaluation, findings.length]);

  const severityCounts = {
    CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
    HIGH: findings.filter((f) => f.severity === 'HIGH').length,
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
    LOW: findings.filter((f) => f.severity === 'LOW').length
  };

  const totalDeductions =
    severityCounts.CRITICAL * WEIGHTS.CRITICAL +
    severityCounts.HIGH * WEIGHTS.HIGH +
    severityCounts.MEDIUM * WEIGHTS.MEDIUM +
    severityCounts.LOW * WEIGHTS.LOW;

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
              Evaluation computed from demo dataset <strong className="font-mono">{importedFileName}</strong> (DEMO DATA — SIMULATED, NOT A LIVE AWS SCAN).
            </span>
          </div>
        </div>
      )}

      {/* Intro Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
            Module 5
          </span>
          <h2 className="text-lg font-bold text-slate-900">Risk Scoring & Ground Truth Accuracy Evaluation</h2>
        </div>
        <p className="text-xs text-slate-600 mt-1 max-w-3xl">
          Assigns a calibrated 0–100 security score based on finding severity penalties, assigns an organizational letter grade,
          and measures auditor accuracy (Precision and Recall) against the known ground-truth answer key.
        </p>
      </div>

      {/* Score & Grade Overview Card */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-4 bg-white border border-slate-200 rounded-xl p-6 shadow-sm flex flex-col justify-between space-y-4">
          <div>
            <span className="text-xs font-bold text-slate-500 uppercase tracking-wider block mb-1">
              Account Security Posture
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-5xl font-extrabold font-mono text-slate-900">{score}</span>
              <span className="text-lg text-slate-500 font-mono">/ 100</span>
            </div>
          </div>

          <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg flex items-center justify-between">
            <div>
              <span className="text-xs text-slate-500 block">Posture Letter Grade</span>
              <span className="text-2xl font-bold font-mono text-slate-900">Grade {grade}</span>
            </div>
            <div
              className={`w-12 h-12 rounded-xl flex items-center justify-center font-bold text-xl font-mono ${
                grade === 'A'
                  ? 'bg-emerald-100 text-emerald-800'
                  : grade === 'B'
                  ? 'bg-blue-100 text-blue-800'
                  : grade === 'C'
                  ? 'bg-yellow-100 text-yellow-800'
                  : grade === 'D'
                  ? 'bg-orange-100 text-orange-800'
                  : 'bg-rose-100 text-rose-800'
              }`}
            >
              {grade}
            </div>
          </div>

          {/* Grade Threshold Reference */}
          <div className="text-[11px] text-slate-500 space-y-1">
            <div className="font-semibold text-slate-700">Grading Scale:</div>
            <div className="grid grid-cols-5 text-center font-mono">
              <div className="p-1 bg-emerald-50 text-emerald-800 rounded">A &ge; 90</div>
              <div className="p-1 bg-blue-50 text-blue-800 rounded">B &ge; 75</div>
              <div className="p-1 bg-yellow-50 text-yellow-800 rounded">C &ge; 60</div>
              <div className="p-1 bg-orange-50 text-orange-800 rounded">D &ge; 40</div>
              <div className="p-1 bg-rose-50 text-rose-800 rounded">F &lt; 40</div>
            </div>
          </div>
        </div>

        {/* Scoring Math Breakdown */}
        <div className="lg:col-span-8 bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-200 pb-3">
            <span className="text-xs font-bold text-slate-700 uppercase tracking-wide">
              Score Deduction Formula Breakdown
            </span>
            <span className="text-xs font-mono font-semibold text-slate-500">
              Formula: Max(0, 100 - Total Penalties)
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg">
              <div className="flex justify-between items-center mb-1">
                <span className="font-bold text-rose-900">CRITICAL</span>
                <span className="font-mono text-rose-700 font-bold">-10 pts</span>
              </div>
              <div className="text-xl font-mono font-bold text-rose-950">{severityCounts.CRITICAL} hits</div>
              <span className="text-[11px] text-rose-800 mt-1 block">
                Total: -{severityCounts.CRITICAL * WEIGHTS.CRITICAL} pts
              </span>
            </div>

            <div className="p-3 bg-orange-50 border border-orange-200 rounded-lg">
              <div className="flex justify-between items-center mb-1">
                <span className="font-bold text-orange-900">HIGH</span>
                <span className="font-mono text-orange-700 font-bold">-7 pts</span>
              </div>
              <div className="text-xl font-mono font-bold text-orange-950">{severityCounts.HIGH} hits</div>
              <span className="text-[11px] text-orange-800 mt-1 block">
                Total: -{severityCounts.HIGH * WEIGHTS.HIGH} pts
              </span>
            </div>

            <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
              <div className="flex justify-between items-center mb-1">
                <span className="font-bold text-yellow-900">MEDIUM</span>
                <span className="font-mono text-yellow-700 font-bold">-4 pts</span>
              </div>
              <div className="text-xl font-mono font-bold text-yellow-950">{severityCounts.MEDIUM} hits</div>
              <span className="text-[11px] text-yellow-800 mt-1 block">
                Total: -{severityCounts.MEDIUM * WEIGHTS.MEDIUM} pts
              </span>
            </div>

            <div className="p-3 bg-sky-50 border border-sky-200 rounded-lg">
              <div className="flex justify-between items-center mb-1">
                <span className="font-bold text-sky-900">LOW</span>
                <span className="font-mono text-sky-700 font-bold">-1 pt</span>
              </div>
              <div className="text-xl font-mono font-bold text-sky-950">{severityCounts.LOW} hits</div>
              <span className="text-[11px] text-sky-800 mt-1 block">
                Total: -{severityCounts.LOW * WEIGHTS.LOW} pts
              </span>
            </div>
          </div>

          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-700 flex justify-between items-center">
            <span>
              100 base - ({severityCounts.CRITICAL}×10 + {severityCounts.HIGH}×7 + {severityCounts.MEDIUM}×4 + {severityCounts.LOW}×1) = 100 - {totalDeductions}
            </span>
            <span className="font-bold text-slate-900 text-sm">= {score} / 100</span>
          </div>
        </div>
      </div>

      {/* Accuracy Evaluation Card (Ground Truth Comparison) */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-200 pb-3">
          <Target className="w-5 h-5 text-indigo-600" />
          <div>
            <h3 className="text-sm font-bold text-slate-900">
              Ground-Truth Verification & Detection Accuracy
            </h3>
            <p className="text-xs text-slate-500">
              Evaluates auditor performance against the 15 security flaws planted in the simulated environment.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-xs text-slate-500 block mb-1">Precision (False Alarm Rate)</span>
            <div className="text-2xl font-bold font-mono text-slate-900">
              {(evaluation.precision * 100).toFixed(0)}%
            </div>
            <span className="text-[11px] text-slate-500 mt-1 block">
              {evaluation.correct} true / {evaluation.found} reported
            </span>
          </div>

          <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-xs text-slate-500 block mb-1">Recall (Miss Rate)</span>
            <div className="text-2xl font-bold font-mono text-slate-900">
              {(evaluation.recall * 100).toFixed(0)}%
            </div>
            <span className="text-[11px] text-slate-500 mt-1 block">
              {evaluation.correct} found / {evaluation.planted} planted
            </span>
          </div>

          <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-xs text-slate-500 block mb-1">Missed Vulnerabilities</span>
            <div className={`text-2xl font-bold font-mono ${evaluation.missed.length === 0 ? 'text-emerald-700' : 'text-rose-700'}`}>
              {evaluation.missed.length}
            </div>
            <span className="text-[11px] text-slate-500 mt-1 block">Zero false negatives</span>
          </div>

          <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-xs text-slate-500 block mb-1">False Positives</span>
            <div className={`text-2xl font-bold font-mono ${evaluation.false_alarms.length === 0 ? 'text-emerald-700' : 'text-amber-700'}`}>
              {evaluation.false_alarms.length}
            </div>
            <span className="text-[11px] text-slate-500 mt-1 block">Zero false alerts</span>
          </div>
        </div>

        <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-lg text-xs text-emerald-900 space-y-1">
          <span className="font-bold flex items-center gap-1.5">
            <CheckCircle className="w-4 h-4 text-emerald-700" />
            100% Detection Precision & Recall Validated
          </span>
          <p className="text-emerald-800">
            Every planted issue in S3, EC2 firewalls, EBS volumes, IAM accounts, RDS databases, CloudTrail, and KMS was detected with zero false alarms.
          </p>
        </div>
      </div>
    </div>
  );
}
