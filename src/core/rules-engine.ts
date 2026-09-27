import {
  AuditCategorySummary,
  AuditFinding,
  AuditReport,
  LetterGrade,
  RemediationStep,
  Severity,
} from "../types/index.js";

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 25,
  HIGH: 12,
  MEDIUM: 6,
  LOW: 2,
  INFO: 0,
};

export function calculateGrade(score: number): LetterGrade {
  if (score >= 95) return "A+";
  if (score >= 85) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

export function buildCategorySummary(
  findings: AuditFinding[],
  passedCount: number
): AuditCategorySummary {
  let deductions = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let infoCount = 0;

  for (const f of findings) {
    deductions += SEVERITY_WEIGHTS[f.severity] || 0;
    if (f.severity === "CRITICAL") criticalCount++;
    else if (f.severity === "HIGH") highCount++;
    else if (f.severity === "MEDIUM") mediumCount++;
    else if (f.severity === "LOW") lowCount++;
    else if (f.severity === "INFO") infoCount++;
  }

  const score = Math.max(0, Math.min(100, 100 - deductions));
  const grade = calculateGrade(score);

  return {
    score,
    grade,
    totalChecks: findings.length + passedCount,
    passedChecks: passedCount,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    infoCount,
  };
}

export function generateRemediationPlan(findings: AuditFinding[]): RemediationStep[] {
  // Sort findings by severity: CRITICAL > HIGH > MEDIUM > LOW > INFO
  const severityOrder: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };

  const sorted = [...findings].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  return sorted.map((f, index) => ({
    step: index + 1,
    title: f.title,
    priority: f.severity,
    action: f.remediation,
    codeSnippet: f.codeSnippet,
    targetFile: f.location,
  }));
}

export function assembleAuditReport(params: {
  target: string;
  targetType: "ENDPOINT" | "CODEBASE" | "FULL";
  durationMs: number;
  owaspFindings: AuditFinding[];
  owaspPassed: string[];
  vibeFindings: AuditFinding[];
  vibePassed: string[];
}): AuditReport {
  const { target, targetType, durationMs, owaspFindings, owaspPassed, vibeFindings, vibePassed } =
    params;

  const owaspSummary = buildCategorySummary(owaspFindings, owaspPassed.length);
  const vibeSummary = buildCategorySummary(vibeFindings, vibePassed.length);

  // Overall score: 60% OWASP Security, 40% Web Vibe / UX
  let overallScore: number;
  if (owaspFindings.length === 0 && owaspPassed.length === 0) {
    overallScore = vibeSummary.score;
  } else if (vibeFindings.length === 0 && vibePassed.length === 0) {
    overallScore = owaspSummary.score;
  } else {
    overallScore = Math.round(owaspSummary.score * 0.6 + vibeSummary.score * 0.4);
  }

  const overallGrade = calculateGrade(overallScore);
  const allFindings = [...owaspFindings, ...vibeFindings];
  const allPassed = [...owaspPassed, ...vibePassed];
  const remediationPlan = generateRemediationPlan(allFindings);

  return {
    target,
    targetType,
    timestamp: new Date().toISOString(),
    durationMs,
    overallScore,
    overallGrade,
    owaspSummary,
    vibeSummary,
    findings: allFindings,
    passedRules: allPassed,
    remediationPlan,
  };
}
