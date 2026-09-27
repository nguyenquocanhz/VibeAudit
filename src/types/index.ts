export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type AuditCategory =
  | "OWASP"
  | "VIBE"
  | "PERFORMANCE"
  | "ACCESSIBILITY"
  | "CODE_HYGIENE";

export type LetterGrade = "A+" | "A" | "B" | "C" | "D" | "F";

export interface AuditFinding {
  id: string;
  title: string;
  category: AuditCategory;
  owaspCategory?: string;
  severity: Severity;
  description: string;
  location?: string;
  evidence?: string;
  impact: string;
  remediation: string;
  codeSnippet?: string;
  autoFixAvailable?: boolean;
}

export interface AuditCategorySummary {
  score: number;
  grade: LetterGrade;
  totalChecks: number;
  passedChecks: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
}

export interface RemediationStep {
  step: number;
  title: string;
  priority: Severity;
  action: string;
  codeSnippet?: string;
  targetFile?: string;
}

export interface AuditReport {
  target: string;
  targetType: "ENDPOINT" | "CODEBASE" | "FULL";
  timestamp: string;
  durationMs: number;
  overallScore: number;
  overallGrade: LetterGrade;
  owaspSummary: AuditCategorySummary;
  vibeSummary: AuditCategorySummary;
  findings: AuditFinding[];
  passedRules: string[];
  remediationPlan: RemediationStep[];
}

export interface AuditOptions {
  url?: string;
  dirPath?: string;
  deepScan?: boolean;
  skipNodeModules?: boolean;
  probeSensitivePaths?: boolean;
  timeoutMs?: number;
}
