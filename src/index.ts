import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import * as path from "path";
import { auditOwaspCodebase } from "./core/owasp-code.js";
import { auditOwaspEndpoint } from "./core/owasp-live.js";
import {
  generateDarkModeSelectCssFix,
  generateHtmlHeadBoilerplate,
  generateSecurityHeadersConfig,
} from "./core/remediator.js";
import { assembleAuditReport } from "./core/rules-engine.js";
import { auditVibeCodebase } from "./core/vibe-code.js";
import { auditVibeEndpoint } from "./core/vibe-live.js";
import { AuditFinding, AuditReport } from "./types/index.js";
import { scanDirectoryFiles } from "./utils/file-scanner.js";
import { fetchEndpointData } from "./utils/http.js";
import { formatMarkdownReport } from "./utils/reporter.js";

const server = new Server(
  {
    name: "vibe-audit",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register Available Tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "vibe_audit_endpoint",
        description:
          "Audit a live web endpoint or API URL for OWASP Top 10 security vulnerabilities and Web Vibe/UX quality (HSTS, CSP, CORS, cookies, mobile viewport, theme flicker, SEO).",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "The HTTP/HTTPS URL of the web endpoint or API to audit.",
            },
            probeSensitivePaths: {
              type: "boolean",
              description: "Whether to probe for exposed /.env, /.git/config, etc.",
              default: false,
            },
          },
          required: ["url"],
        },
      },
      {
        name: "vibe_audit_codebase",
        description:
          "Audit a local project directory for security vulnerabilities (hardcoded secrets, XSS sinks, dangerous eval, committed .env) and Web Vibe flaws (Chromium Dark Mode <select> option contrast rule, console leaks, blocking alerts).",
        inputSchema: {
          type: "object",
          properties: {
            path: {
              type: "string",
              description: "Absolute or relative path to the project directory.",
            },
          },
          required: ["path"],
        },
      },
      {
        name: "vibe_audit_full",
        description:
          "Perform a unified full-spectrum audit combining live endpoint checks and local codebase analysis.",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "Live URL of the deployed application (optional).",
            },
            path: {
              type: "string",
              description: "Path to local codebase repository (optional).",
            },
            probeSensitivePaths: {
              type: "boolean",
              default: false,
            },
          },
        },
      },
      {
        name: "vibe_get_remediation",
        description:
          "Retrieve ready-to-copy code fixes and server configurations (Nginx, Apache, Express, PHP, CSS Dark Mode Select contrast patch, HTML head).",
        inputSchema: {
          type: "object",
          properties: {
            type: {
              type: "string",
              enum: [
                "nginx",
                "apache",
                "express",
                "php",
                "darkmode-select",
                "html-head",
                "all",
              ],
              description: "The remediation category or framework target.",
            },
          },
          required: ["type"],
        },
      },
      {
        name: "vibe_quick_check",
        description:
          "Perform an ultra-fast check on a URL, returning overall score (0-100), letter grade (A+ to F), and top vulnerabilities.",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "Target URL to inspect.",
            },
          },
          required: ["url"],
        },
      },
    ],
  };
});

// Handle Tool Calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const startTime = Date.now();

  try {
    if (name === "vibe_audit_endpoint") {
      const url = String(args?.url);
      const probe = Boolean(args?.probeSensitivePaths);

      const httpData = await fetchEndpointData(url);
      const liveOwasp = await auditOwaspEndpoint(httpData, { probeSensitivePaths: probe });
      const liveVibe = auditVibeEndpoint(httpData);

      const report = assembleAuditReport({
        target: url,
        targetType: "ENDPOINT",
        durationMs: Date.now() - startTime,
        owaspFindings: liveOwasp.findings,
        owaspPassed: liveOwasp.passedRules,
        vibeFindings: liveVibe.findings,
        vibePassed: liveVibe.passedRules,
      });

      return {
        content: [
          {
            type: "text",
            text: formatMarkdownReport(report),
          },
        ],
      };
    }

    if (name === "vibe_audit_codebase") {
      const dirPath = path.resolve(String(args?.path));
      const files = await scanDirectoryFiles(dirPath);

      const codeOwasp = await auditOwaspCodebase(files);
      const codeVibe = await auditVibeCodebase(files);

      const report = assembleAuditReport({
        target: dirPath,
        targetType: "CODEBASE",
        durationMs: Date.now() - startTime,
        owaspFindings: codeOwasp.findings,
        owaspPassed: codeOwasp.passedRules,
        vibeFindings: codeVibe.findings,
        vibePassed: codeVibe.passedRules,
      });

      return {
        content: [
          {
            type: "text",
            text: formatMarkdownReport(report),
          },
        ],
      };
    }

    if (name === "vibe_audit_full") {
      const url = args?.url ? String(args.url) : undefined;
      const dirPath = args?.path ? path.resolve(String(args.path)) : undefined;
      const probe = Boolean(args?.probeSensitivePaths);

      let owaspFindings: AuditFinding[] = [];
      let owaspPassed: string[] = [];
      let vibeFindings: AuditFinding[] = [];
      let vibePassed: string[] = [];
      let targetDesc = [];

      if (url) {
        targetDesc.push(`URL: ${url}`);
        const httpData = await fetchEndpointData(url);
        const liveOwasp = await auditOwaspEndpoint(httpData, { probeSensitivePaths: probe });
        const liveVibe = auditVibeEndpoint(httpData);
        owaspFindings.push(...liveOwasp.findings);
        owaspPassed.push(...liveOwasp.passedRules);
        vibeFindings.push(...liveVibe.findings);
        vibePassed.push(...liveVibe.passedRules);
      }

      if (dirPath) {
        targetDesc.push(`DIR: ${dirPath}`);
        const files = await scanDirectoryFiles(dirPath);
        const codeOwasp = await auditOwaspCodebase(files);
        const codeVibe = await auditVibeCodebase(files);
        owaspFindings.push(...codeOwasp.findings);
        owaspPassed.push(...codeOwasp.passedRules);
        vibeFindings.push(...codeVibe.findings);
        vibePassed.push(...codeVibe.passedRules);
      }

      const report = assembleAuditReport({
        target: targetDesc.join(" | ") || "Empty target",
        targetType: "FULL",
        durationMs: Date.now() - startTime,
        owaspFindings,
        owaspPassed,
        vibeFindings,
        vibePassed,
      });

      return {
        content: [
          {
            type: "text",
            text: formatMarkdownReport(report),
          },
        ],
      };
    }

    if (name === "vibe_quick_check") {
      const url = String(args?.url);
      const httpData = await fetchEndpointData(url);
      const liveOwasp = await auditOwaspEndpoint(httpData);
      const liveVibe = auditVibeEndpoint(httpData);

      const report = assembleAuditReport({
        target: url,
        targetType: "ENDPOINT",
        durationMs: Date.now() - startTime,
        owaspFindings: liveOwasp.findings,
        owaspPassed: liveOwasp.passedRules,
        vibeFindings: liveVibe.findings,
        vibePassed: liveVibe.passedRules,
      });

      const summary = {
        target: url,
        status: httpData.statusCode,
        responseTimeMs: httpData.responseTimeMs,
        score: report.overallScore,
        grade: report.overallGrade,
        securityScore: report.owaspSummary.score,
        vibeScore: report.vibeSummary.score,
        criticalIssues: report.findings
          .filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH")
          .map((f) => `[${f.severity}] ${f.title}`),
      };

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(summary, null, 2),
          },
        ],
      };
    }

    if (name === "vibe_get_remediation") {
      const type = String(args?.type || "all");
      const configs = generateSecurityHeadersConfig();

      let responseText = "";

      if (type === "darkmode-select" || type === "all") {
        responseText += `### Chromium Dark Mode <select> Option Contrast Fix\n\`\`\`css\n${generateDarkModeSelectCssFix()}\n\`\`\`\n\n`;
      }
      if (type === "nginx" || type === "all") {
        responseText += `### Nginx Security Headers Configuration\n\`\`\`nginx\n${configs.nginx.config}\n\`\`\`\n\n`;
      }
      if (type === "apache" || type === "all") {
        responseText += `### Apache .htaccess Configuration\n\`\`\`apache\n${configs.apache.config}\n\`\`\`\n\n`;
      }
      if (type === "express" || type === "all") {
        responseText += `### Express.js Helmet Configuration\n\`\`\`javascript\n${configs.express.config}\n\`\`\`\n\n`;
      }
      if (type === "php" || type === "all") {
        responseText += `### PHP Native Headers Configuration\n\`\`\`php\n${configs.php.config}\n\`\`\`\n\n`;
      }
      if (type === "html-head" || type === "all") {
        responseText += `### Modern Responsive & Social <head> Template\n\`\`\`html\n${generateHtmlHeadBoilerplate()}\n\`\`\`\n\n`;
      }

      return {
        content: [
          {
            type: "text",
            text: responseText,
          },
        ],
      };
    }

    throw new Error(`Unknown tool name: ${name}`);
  } catch (err: any) {
    return {
      content: [
        {
          type: "text",
          text: `VibeAudit Error: ${err.message || String(err)}`,
        },
      ],
      isError: true,
    };
  }
});

// Start MCP Server over stdio
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("VibeAudit MCP Server running on stdio");
}

main().catch((err) => {
  console.error("Fatal error starting VibeAudit MCP Server:", err);
  process.exit(1);
});
