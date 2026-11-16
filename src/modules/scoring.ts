import { Finding, Severity, GroundTruthItem, AccuracyEvaluation } from '../types/security';

export const WEIGHTS: Record<Severity, number> = {
  CRITICAL: 10,
  HIGH: 7,
  MEDIUM: 4,
  LOW: 1
};

export function calculateSecurityScore(findings: Finding[]): number {
  if (findings.length === 0) {
    return 100;
  }
  const deductions = findings.reduce((acc, f) => acc + (WEIGHTS[f.severity] || 0), 0);
  return Math.max(0, 100 - deductions);
}

export function calculateGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export function evaluateAccuracy(findings: Finding[], groundTruth: GroundTruthItem[]): AccuracyEvaluation {
  const foundSet = new Set(findings.map((f) => `${f.resource}::${f.rule_id}`));
  const plantedSet = new Set(groundTruth.map((item) => `${item.resource}::${item.rule_id}`));

  let truePositives = 0;
  foundSet.forEach((item) => {
    if (plantedSet.has(item)) {
      truePositives += 1;
    }
  });

  const precision = foundSet.size > 0 ? Number((truePositives / foundSet.size).toFixed(2)) : 0;
  const recall = plantedSet.size > 0 ? Number((truePositives / plantedSet.size).toFixed(2)) : 0;

  const missed: GroundTruthItem[] = [];
  plantedSet.forEach((item) => {
    if (!foundSet.has(item)) {
      const [resource, rule_id] = item.split('::');
      missed.push({ resource, rule_id });
    }
  });

  const false_alarms: GroundTruthItem[] = [];
  foundSet.forEach((item) => {
    if (!plantedSet.has(item)) {
      const [resource, rule_id] = item.split('::');
      false_alarms.push({ resource, rule_id });
    }
  });

  return {
    planted: groundTruth.length,
    found: findings.length,
    correct: truePositives,
    precision,
    recall,
    missed,
    false_alarms
  };
}
