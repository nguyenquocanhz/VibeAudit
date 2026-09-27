import * as path from "path";
import { AuditFinding } from "../types/index.js";
import { ScannedFile } from "../utils/file-scanner.js";

interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: AuditFinding["severity"];
  owaspCategory: string;
  description: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "AWS Access Key",
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    severity: "CRITICAL",
    owaspCategory: "A02:2021-Cryptographic Failures",
    description: "Hardcoded AWS Access Key detected.",
  },
  {
    name: "GitHub Token",
    regex: /\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b/g,
    severity: "CRITICAL",
    owaspCategory: "A02:2021-Cryptographic Failures",
    description: "Hardcoded GitHub Personal Access Token detected.",
  },
  {
    name: "OpenAI Secret Key",
    regex: /\b(sk-[a-zA-Z0-9T3BlbkFJ]{32,})\b/g,
    severity: "CRITICAL",
    owaspCategory: "A02:2021-Cryptographic Failures",
    description: "Hardcoded OpenAI API Secret Key detected.",
  },
  {
    name: "Google API Key",
    regex: /\b(AIza[0-9A-Za-z\\-_]{35})\b/g,
    severity: "HIGH",
    owaspCategory: "A02:2021-Cryptographic Failures",
    description: "Hardcoded Google API Key detected.",
  },
  {
    name: "Slack Token",
    regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/g,
    severity: "CRITICAL",
    owaspCategory: "A02:2021-Cryptographic Failures",
    description: "Hardcoded Slack API Token detected.",
  },
  {
    name: "Private Key Header",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: "CRITICAL",
    owaspCategory: "A02:2021-Cryptographic Failures",
    description: "Hardcoded cryptographic private key block detected.",
  },
  {
    name: "Database Connection URI with Credentials",
    regex: /(?:mongodb(?:\+srv)?|postgres|postgresql|mysql):\/\/[^:\/\s]+:[^@\/\s]+@[a-zA-Z0-9\.\-_]+/g,
    severity: "CRITICAL",
    owaspCategory: "A02:2021-Cryptographic Failures",
    description: "Hardcoded database connection string containing embedded credentials.",
  },
];

export async function auditOwaspCodebase(
  files: ScannedFile[]
): Promise<{ findings: AuditFinding[]; passedRules: string[] }> {
  const findings: AuditFinding[] = [];
  const passedRules: string[] = [];

  let hasGitignore = false;
  let gitignoreContent = "";

  for (const file of files) {
    const baseName = path.basename(file.relativePath).toLowerCase();

    // Track .gitignore
    if (baseName === ".gitignore") {
      hasGitignore = true;
      gitignoreContent = file.content;
    }

    // 1. Check for committed sensitive .env files
    if (baseName.startsWith(".env") && baseName !== ".env.example" && baseName !== ".env.template") {
      findings.push({
        id: "OWASP-ENV-FILE-COMMITTED",
        title: `Sensitive Environment File Found: ${file.relativePath}`,
        category: "OWASP",
        owaspCategory: "A05:2021-Security Misconfiguration",
        severity: "HIGH",
        description: `An active environment file (${file.relativePath}) was found in the project.`,
        location: file.relativePath,
        impact: "Exposes environment secrets, DB passwords, and private tokens to anyone with repo access.",
        remediation: "Add .env* to .gitignore and rotate any committed secrets immediately.",
      });
    }

    // 2. Scan lines for hardcoded secrets
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const lineNum = i + 1;

      // Skip comment-only lines or tests
      if (line.trim().startsWith("//") || line.trim().startsWith("#") || line.trim().startsWith("*")) {
        continue;
      }

      // Check regex secret patterns
      for (const pattern of SECRET_PATTERNS) {
        pattern.regex.lastIndex = 0;
        if (pattern.regex.test(line)) {
          findings.push({
            id: `OWASP-SECRET-${pattern.name.toUpperCase().replace(/\s+/g, "_")}`,
            title: `Potential Secret Leak: ${pattern.name}`,
            category: "OWASP",
            owaspCategory: pattern.owaspCategory,
            severity: pattern.severity,
            description: `${pattern.description} Found in ${file.relativePath}:${lineNum}.`,
            location: `${file.relativePath}:${lineNum}`,
            evidence: line.trim().slice(0, 80),
            impact: "Severe risk of cloud account takeover, API abuse, and data theft.",
            remediation: "Store secrets in environment variables or a Secret Manager (e.g. AWS Secrets Manager, Vault).",
          });
        }
      }

      // 3. Dangerous JavaScript/PHP execution sinks (eval, Function, dangerous exec)
      const isRegexDeclaration = /\/.*eval.*\/|\.test\(|regex:/.test(line);
      if (/\beval\s*\(/.test(line) && !line.includes("JSON.parse") && !isRegexDeclaration) {
        findings.push({
          id: "OWASP-INJECTION-EVAL",
          title: "Dangerous Code Execution Sink: eval()",
          category: "OWASP",
          owaspCategory: "A03:2021-Injection",
          severity: "HIGH",
          description: `Use of eval() detected in ${file.relativePath}:${lineNum}.`,
          location: `${file.relativePath}:${lineNum}`,
          evidence: line.trim().slice(0, 80),
          impact: "Allows arbitrary code execution if dynamic input reaches eval().",
          remediation: "Refactor code to use JSON.parse(), direct property access, or typed dispatchers.",
        });
      }

      // 4. React dangerouslySetInnerHTML or Vue v-html without DOMPurify
      const isHtmlSinkDecl = /dangerouslySetInnerHTML|v-html/.test(line) && !isRegexDeclaration;
      if (isHtmlSinkDecl && !line.includes("DOMPurify.sanitize")) {
        findings.push({
          id: "OWASP-XSS-DANGEROUS-HTML",
          title: "Raw HTML Injection Sink (XSS Risk)",
          category: "OWASP",
          owaspCategory: "A03:2021-Injection",
          severity: "MEDIUM",
          description: `Direct HTML rendering via dangerouslySetInnerHTML or v-html in ${file.relativePath}:${lineNum}.`,
          location: `${file.relativePath}:${lineNum}`,
          evidence: line.trim().slice(0, 80),
          impact: "Unsanitized user content rendered as HTML can execute arbitrary JavaScript in the victim's browser.",
          remediation: "Sanitize HTML using DOMPurify (e.g. DOMPurify.sanitize(input)) or render as plain text children.",
        });
      }

      // 5. Insecure HTTP Calls
      if (/fetch\s*\(\s*['"]http:\/\//i.test(line) || /axios\.[a-z]+\s*\(\s*['"]http:\/\//i.test(line)) {
        findings.push({
          id: "OWASP-INSECURE-HTTP-CALL",
          title: "Insecure Plaintext HTTP API Request",
          category: "OWASP",
          owaspCategory: "A02:2021-Cryptographic Failures",
          severity: "MEDIUM",
          description: `Outbound API request made over plaintext HTTP in ${file.relativePath}:${lineNum}.`,
          location: `${file.relativePath}:${lineNum}`,
          evidence: line.trim().slice(0, 80),
          impact: "Traffic can be intercepted or altered by MITM attacks on the network.",
          remediation: "Change the URL protocol from http:// to https://.",
        });
      }
    }
  }

  // Check .gitignore status
  if (!hasGitignore) {
    findings.push({
      id: "OWASP-GITIGNORE-MISSING",
      title: "Missing .gitignore File",
      category: "OWASP",
      owaspCategory: "A05:2021-Security Misconfiguration",
      severity: "MEDIUM",
      description: "Project lacks a .gitignore file, risking accidental commits of node_modules, keys, or .env files.",
      location: ".gitignore",
      impact: "Secrets and development artifacts can be leaked to source control.",
      remediation: "Create a .gitignore file ignoring .env, node_modules, dist, and private keys.",
      codeSnippet: `.env\n.env.*\nnode_modules/\ndist/\n*.pem\n*.key`,
    });
  } else {
    if (!gitignoreContent.includes(".env")) {
      findings.push({
        id: "OWASP-GITIGNORE-NO-ENV",
        title: ".env Not Listed in .gitignore",
        category: "OWASP",
        owaspCategory: "A05:2021-Security Misconfiguration",
        severity: "HIGH",
        description: "The .gitignore file exists but does not ignore .env files.",
        location: ".gitignore",
        impact: "Future local environment files with secrets may accidentally be committed.",
        remediation: "Add .env and .env.* to .gitignore.",
      });
    } else {
      passedRules.push("OWASP-GITIGNORE-PROTECTS-ENV");
    }
  }

  if (findings.length === 0) {
    passedRules.push("OWASP-NO-SECRETS-LEAKED");
  }

  return { findings, passedRules };
}
