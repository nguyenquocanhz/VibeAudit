import chalk from "chalk";
import { AuditReport, Severity } from "../types/index.js";

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  CRITICAL: chalk.bgRed.white.bold,
  HIGH: chalk.red.bold,
  MEDIUM: chalk.yellow.bold,
  LOW: chalk.cyan,
  INFO: chalk.gray,
};

const GRADE_COLORS: Record<string, (s: string) => string> = {
  "A+": chalk.greenBright.bold,
  A: chalk.green.bold,
  B: chalk.blueBright.bold,
  C: chalk.yellowBright.bold,
  D: chalk.hex("#FFA500").bold,
  F: chalk.redBright.bold,
};

export function formatTerminalSummary(report: AuditReport): string {
  const lines: string[] = [];
  const bar = "=".repeat(65);

  lines.push("");
  lines.push(chalk.bold.magenta(bar));
  lines.push(
    chalk.bold.cyan("               🛡️   VIBE-AUDIT COMPREHENSIVE REPORT   🛡️")
  );
  lines.push(
    chalk.gray(
      `        Target: ${report.target} | Time: ${report.durationMs}ms`
    )
  );
  lines.push(chalk.bold.magenta(bar));
  lines.push("");

  // Score & Grade Cards
  const gradeColor = GRADE_COLORS[report.overallGrade] || chalk.white;
  lines.push(
    `  ${chalk.bold("OVERALL GRADE:")} ${gradeColor(
      `[ ${report.overallGrade} ]`
    )}  ${chalk.bold("OVERALL SCORE:")} ${gradeColor(
      `${report.overallScore}/100`
    )}`
  );

  lines.push(
    `  ${chalk.bold("OWASP Security:")} ${report.owaspSummary.grade} (${report.owaspSummary.score}/100) | ` +
      `${chalk.bold("Web Vibe / UX:")} ${report.vibeSummary.grade} (${report.vibeSummary.score}/100)`
  );
  lines.push("");

  // Findings Counters
  const crit = report.findings.filter((f) => f.severity === "CRITICAL").length;
  const high = report.findings.filter((f) => f.severity === "HIGH").length;
  const med = report.findings.filter((f) => f.severity === "MEDIUM").length;
  const low = report.findings.filter((f) => f.severity === "LOW").length;

  lines.push(
    `  Findings: ${chalk.red.bold(`${crit} Critical`)} | ${chalk.hex("#FF7700").bold(
      `${high} High`
    )} | ${chalk.yellow.bold(`${med} Medium`)} | ${chalk.cyan(`${low} Low`)} | ${chalk.green(
      `${report.passedRules.length} Passed Rules`
    )}`
  );
  lines.push(chalk.gray("-".repeat(65)));

  // Highlight Key Findings
  if (report.findings.length === 0) {
    lines.push(
      chalk.green.bold(
        "  ✨ Zero vulnerabilities found! Immaculate Web Vibe & Security."
      )
    );
  } else {
    lines.push(chalk.bold.underline("  Top Issues Detected:"));
    lines.push("");
    for (const f of report.findings.slice(0, 8)) {
      const tag = SEVERITY_COLORS[f.severity](`[${f.severity}]`);
      lines.push(`  ${tag} ${chalk.bold(f.title)}`);
      lines.push(`     ${chalk.gray("Category:")} ${f.category} ${f.owaspCategory ? `(${f.owaspCategory})` : ""}`);
      if (f.location) {
        lines.push(`     ${chalk.gray("Location:")} ${chalk.yellow(f.location)}`);
      }
      lines.push(`     ${chalk.gray("Action:")}   ${f.remediation}`);
      lines.push("");
    }

    if (report.findings.length > 8) {
      lines.push(
        chalk.gray(
          `  ... and ${report.findings.length - 8} more issues. Run with --output report.md for full report.`
        )
      );
      lines.push("");
    }
  }

  lines.push(chalk.bold.magenta(bar));
  lines.push("");
  return lines.join("\n");
}

export function formatMarkdownReport(report: AuditReport): string {
  const md: string[] = [];

  md.push(`# 🛡️ VibeAudit Report`);
  md.push(`**Target**: \`${report.target}\`  `);
  md.push(`**Audit Type**: \`${report.targetType}\`  `);
  md.push(`**Generated**: ${report.timestamp}  `);
  md.push(`**Duration**: ${report.durationMs}ms\n`);

  md.push(`## 📊 Executive Summary`);
  md.push(`| Metric | Value | Rating |`);
  md.push(`|---|---|---|`);
  md.push(`| **Overall Vibe & Security Score** | **${report.overallScore}/100** | **${report.overallGrade}** |`);
  md.push(`| **OWASP Top 10 Security** | ${report.owaspSummary.score}/100 | ${report.owaspSummary.grade} |`);
  md.push(`| **Web Vibe & UX Quality** | ${report.vibeSummary.score}/100 | ${report.vibeSummary.grade} |`);
  md.push(`| **Total Checks Passed** | ${report.passedRules.length} | ✅ |`);
  md.push(`| **Total Findings** | ${report.findings.length} | ⚠️ |\n`);

  md.push(`### Severity Breakdown`);
  md.push(`- **Critical**: ${report.findings.filter((f) => f.severity === "CRITICAL").length}`);
  md.push(`- **High**: ${report.findings.filter((f) => f.severity === "HIGH").length}`);
  md.push(`- **Medium**: ${report.findings.filter((f) => f.severity === "MEDIUM").length}`);
  md.push(`- **Low**: ${report.findings.filter((f) => f.severity === "LOW").length}\n`);

  md.push(`## 🚨 Discovered Findings`);
  if (report.findings.length === 0) {
    md.push(`*No issues discovered! Project is in pristine condition.*\n`);
  } else {
    for (const f of report.findings) {
      md.push(`### [${f.severity}] ${f.title}`);
      md.push(`- **ID**: \`${f.id}\``);
      md.push(`- **Category**: \`${f.category}\` ${f.owaspCategory ? `(\`${f.owaspCategory}\`)` : ""}`);
      if (f.location) md.push(`- **Location**: \`${f.location}\``);
      if (f.evidence) md.push(`- **Evidence**: \`${f.evidence}\``);
      md.push(`- **Description**: ${f.description}`);
      md.push(`- **Impact**: ${f.impact}`);
      md.push(`- **Remediation**: ${f.remediation}`);

      if (f.codeSnippet) {
        md.push(`\n\`\`\`${f.codeSnippet.startsWith("<") ? "html" : "css"}\n${f.codeSnippet}\n\`\`\`\n`);
      }
      md.push(`---\n`);
    }
  }

  md.push(`## 🛠️ Prioritized Remediation Plan`);
  for (const step of report.remediationPlan) {
    md.push(`#### Step ${step.step}: ${step.title} (${step.priority})`);
    md.push(`- **Action**: ${step.action}`);
    if (step.targetFile) md.push(`- **Target**: \`${step.targetFile}\``);
    if (step.codeSnippet) {
      md.push(`\`\`\`\n${step.codeSnippet}\n\`\`\`\n`);
    }
  }

  md.push(`\n---\n*Report generated by [VibeAudit](https://github.com/nguyenquocanhz/VibeAudit)*`);
  return md.join("\n");
}
