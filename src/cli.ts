#!/usr/bin/env node

import { Command } from "commander";
import * as fs from "fs";
import * as path from "path";
import { auditOwaspCodebase } from "./core/owasp-code.js";
import { auditOwaspEndpoint } from "./core/owasp-live.js";
import {
  generateDarkModeSelectCssFix,
  generateSecurityHeadersConfig,
} from "./core/remediator.js";
import { assembleAuditReport } from "./core/rules-engine.js";
import { auditVibeCodebase } from "./core/vibe-code.js";
import { auditVibeEndpoint } from "./core/vibe-live.js";
import { AuditFinding, AuditReport } from "./types/index.js";
import { scanDirectoryFiles } from "./utils/file-scanner.js";
import { fetchEndpointData } from "./utils/http.js";
import { formatMarkdownReport, formatTerminalSummary } from "./utils/reporter.js";

const program = new Command();

program
  .name("vibe-audit")
  .description("VibeAudit: OWASP Top 10 Security & Web Vibe/UX Quality Auditor")
  .version("1.0.0")
  .option("-u, --url <url>", "Live web endpoint or API URL to audit")
  .option("-d, --dir <path>", "Local directory/codebase to audit")
  .option("-p, --probe", "Probe sensitive paths (/.env, /.git, etc.) on live URL", false)
  .option("-o, --output <file>", "Export markdown report to specified file")
  .option("-j, --json", "Output machine-readable JSON result", false)
  .option("--fix", "Display auto-remediation snippets for detected issues", false)
  .action(async (options) => {
    if (!options.url && !options.dir) {
      console.log("Error: Please provide at least --url <url> or --dir <path>");
      program.help();
      process.exit(1);
    }

    const startTime = Date.now();
    let owaspFindings: AuditFinding[] = [];
    let owaspPassed: string[] = [];
    let vibeFindings: AuditFinding[] = [];
    let vibePassed: string[] = [];
    let target = "";
    let targetType: AuditReport["targetType"] = "FULL";

    try {
      // 1. Audit Live Endpoint if provided
      if (options.url) {
        target = options.url;
        targetType = options.dir ? "FULL" : "ENDPOINT";

        const httpData = await fetchEndpointData(options.url);
        const liveOwasp = await auditOwaspEndpoint(httpData, {
          probeSensitivePaths: options.probe,
        });
        const liveVibe = auditVibeEndpoint(httpData);

        owaspFindings.push(...liveOwasp.findings);
        owaspPassed.push(...liveOwasp.passedRules);
        vibeFindings.push(...liveVibe.findings);
        vibePassed.push(...liveVibe.passedRules);
      }

      // 2. Audit Codebase if provided
      if (options.dir) {
        const resolvedDir = path.resolve(options.dir);
        if (!target) {
          target = resolvedDir;
          targetType = "CODEBASE";
        } else {
          target = `${target} + ${resolvedDir}`;
        }

        const files = await scanDirectoryFiles(resolvedDir);
        const codeOwasp = await auditOwaspCodebase(files);
        const codeVibe = await auditVibeCodebase(files);

        owaspFindings.push(...codeOwasp.findings);
        owaspPassed.push(...codeOwasp.passedRules);
        vibeFindings.push(...codeVibe.findings);
        vibePassed.push(...codeVibe.passedRules);
      }

      const durationMs = Date.now() - startTime;
      const report = assembleAuditReport({
        target,
        targetType,
        durationMs,
        owaspFindings,
        owaspPassed,
        vibeFindings,
        vibePassed,
      });

      // Output Handling
      if (options.json) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        console.log(formatTerminalSummary(report));

        if (options.fix) {
          console.log("\n🛠️  AUTO-REMEDIATION SNIPPETS:");
          console.log("--------------------------------------------------");
          console.log(generateDarkModeSelectCssFix());
          const configs = generateSecurityHeadersConfig();
          console.log("// Nginx Security Config:");
          console.log(configs.nginx.config);
        }
      }

      if (options.output) {
        const md = formatMarkdownReport(report);
        fs.writeFileSync(path.resolve(options.output), md, "utf-8");
        console.log(`\n📄 Full Markdown report exported to: ${path.resolve(options.output)}`);
      }

      // Exit code: 0 if no criticals/highs, 1 if critical/high findings exist
      const hasCriticalOrHigh = report.findings.some(
        (f) => f.severity === "CRITICAL" || f.severity === "HIGH"
      );
      if (hasCriticalOrHigh) {
        process.exitCode = 1;
      }
    } catch (err: any) {
      console.error("VibeAudit execution failed:", err.message || err);
      process.exit(1);
    }
  });

program.parse(process.argv);
