import { AuditFinding } from "../types/index.js";
import { HttpResponseData, probePath } from "../utils/http.js";

export async function auditOwaspEndpoint(
  res: HttpResponseData,
  options: { probeSensitivePaths?: boolean } = {}
): Promise<{ findings: AuditFinding[]; passedRules: string[] }> {
  const findings: AuditFinding[] = [];
  const passedRules: string[] = [];

  const headers = res.headers;
  const isHttps = res.url.startsWith("https://");

  // 1. TLS & Encryption Check
  if (!isHttps) {
    findings.push({
      id: "OWASP-CRYPTO-NO-HTTPS",
      title: "Insecure Plaintext Transport (No HTTPS)",
      category: "OWASP",
      owaspCategory: "A02:2021-Cryptographic Failures",
      severity: "CRITICAL",
      description:
        "The target is accessible over unencrypted HTTP. All credentials, tokens, and data can be intercepted by MITM attackers.",
      location: res.url,
      impact: "Total compromise of confidentiality and session security.",
      remediation: "Enforce HTTPS with an SSL/TLS certificate and configure 301 Permanent Redirects from HTTP to HTTPS.",
      codeSnippet: `// Nginx HTTPS Redirect:
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}`,
    });
  } else {
    passedRules.push("OWASP-CRYPTO-HTTPS-ENABLED");
    if (res.tlsInfo && !res.tlsInfo.authorized) {
      findings.push({
        id: "OWASP-CRYPTO-INVALID-CERT",
        title: "Untrusted or Invalid SSL/TLS Certificate",
        category: "OWASP",
        owaspCategory: "A02:2021-Cryptographic Failures",
        severity: "HIGH",
        description: "The SSL/TLS certificate failed validation or is self-signed/expired.",
        location: res.url,
        impact: "Users will face browser warnings and vulnerability to spoofing.",
        remediation: "Deploy a valid certificate issued by a recognized CA (such as Let's Encrypt).",
      });
    }
  }

  // 2. Strict-Transport-Security (HSTS)
  const hsts = headers["strict-transport-security"];
  if (!hsts) {
    findings.push({
      id: "OWASP-HSTS-MISSING",
      title: "Missing HTTP Strict Transport Security (HSTS) Header",
      category: "OWASP",
      owaspCategory: "A05:2021-Security Misconfiguration",
      severity: "HIGH",
      description:
        "HSTS header instructs browsers to strictly communicate over HTTPS, preventing SSL-stripping attacks.",
      location: "HTTP Header: Strict-Transport-Security",
      impact: "Attackers on the same network can downgrade user traffic to plaintext HTTP.",
      remediation: "Add Strict-Transport-Security header with at least 1 year duration and includeSubDomains.",
      codeSnippet: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`,
    });
  } else {
    passedRules.push("OWASP-HSTS-PRESENT");
    if (!hsts.includes("max-age") || parseInt(hsts.match(/max-age=(\d+)/)?.[1] || "0") < 15552000) {
      findings.push({
        id: "OWASP-HSTS-SHORT-MAXAGE",
        title: "HSTS max-age is Too Short (< 180 Days)",
        category: "OWASP",
        owaspCategory: "A05:2021-Security Misconfiguration",
        severity: "LOW",
        description: `Current HSTS max-age is below recommended 180-365 days. Value: "${hsts}"`,
        location: "Strict-Transport-Security",
        impact: "Protection expires quickly if the user does not revisit frequently.",
        remediation: "Increase max-age to 31536000 (1 year).",
      });
    }
  }

  // 3. Content-Security-Policy (CSP)
  const csp = headers["content-security-policy"];
  if (!csp) {
    findings.push({
      id: "OWASP-CSP-MISSING",
      title: "Missing Content-Security-Policy (CSP) Header",
      category: "OWASP",
      owaspCategory: "A05:2021-Security Misconfiguration",
      severity: "MEDIUM",
      description:
        "CSP prevents Cross-Site Scripting (XSS), data injection, and malicious script execution by whitelisting trusted origins.",
      location: "HTTP Header: Content-Security-Policy",
      impact: "High susceptibility to XSS and client-side data exfiltration.",
      remediation: "Define a restrictive CSP policy restricting script-src, object-src, and default-src.",
      codeSnippet: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';`,
    });
  } else {
    passedRules.push("OWASP-CSP-PRESENT");
    if (csp.includes("'unsafe-eval'") || (csp.includes("'unsafe-inline'") && !csp.includes("'nonce-"))) {
      findings.push({
        id: "OWASP-CSP-WEAK",
        title: "Permissive Content-Security-Policy Directives",
        category: "OWASP",
        owaspCategory: "A03:2021-Injection",
        severity: "LOW",
        description: `CSP includes 'unsafe-inline' or 'unsafe-eval' which weakens protection against XSS. Value: "${csp.slice(0, 100)}..."`,
        location: "Content-Security-Policy",
        impact: "Injected scripts may still execute if an XSS vulnerability exists.",
        remediation: "Migrate inline scripts to external modules and use CSP nonces/hashes.",
      });
    }
  }

  // 4. Clickjacking: X-Frame-Options
  const xfo = headers["x-frame-options"];
  const cspFrame = csp?.includes("frame-ancestors");
  if (!xfo && !cspFrame) {
    findings.push({
      id: "OWASP-CLICKJACKING-UNPROTECTED",
      title: "Missing Clickjacking Protection (X-Frame-Options)",
      category: "OWASP",
      owaspCategory: "A01:2021-Broken Access Control",
      severity: "MEDIUM",
      description:
        "Neither X-Frame-Options nor CSP frame-ancestors is configured. The page can be embedded inside an attacker's <iframe>.",
      location: "HTTP Header: X-Frame-Options",
      impact: "Attackers can trick authenticated users into clicking buttons or submitting forms unwittingly (Clickjacking).",
      remediation: "Set X-Frame-Options to DENY or SAMEORIGIN, or specify frame-ancestors in CSP.",
      codeSnippet: `X-Frame-Options: SAMEORIGIN`,
    });
  } else {
    passedRules.push("OWASP-CLICKJACKING-PROTECTED");
  }

  // 5. X-Content-Type-Options: nosniff
  const xcto = headers["x-content-type-options"];
  if (!xcto || !xcto.toLowerCase().includes("nosniff")) {
    findings.push({
      id: "OWASP-MIME-SNIFFING",
      title: "Missing X-Content-Type-Options: nosniff",
      category: "OWASP",
      owaspCategory: "A05:2021-Security Misconfiguration",
      severity: "LOW",
      description:
        "Missing nosniff allows browsers to MIME-sniff response bodies away from the declared content-type, potentially executing text/plain as HTML/JavaScript.",
      location: "HTTP Header: X-Content-Type-Options",
      impact: "MIME confusion attacks and unauthorized script execution.",
      remediation: "Set X-Content-Type-Options: nosniff on all responses.",
      codeSnippet: `X-Content-Type-Options: nosniff`,
    });
  } else {
    passedRules.push("OWASP-MIME-SNIFFING-PREVENTED");
  }

  // 6. Referrer-Policy
  const refPolicy = headers["referrer-policy"];
  if (!refPolicy) {
    findings.push({
      id: "OWASP-REFERRER-POLICY-MISSING",
      title: "Missing Referrer-Policy Header",
      category: "OWASP",
      owaspCategory: "A05:2021-Security Misconfiguration",
      severity: "LOW",
      description:
        "Without Referrer-Policy, full URLs containing sensitive tokens, query parameters, or internal routes may leak in Referer headers to external links.",
      location: "HTTP Header: Referrer-Policy",
      impact: "Token leakage and sensitive endpoint exposure.",
      remediation: "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
      codeSnippet: `Referrer-Policy: strict-origin-when-cross-origin`,
    });
  } else {
    passedRules.push("OWASP-REFERRER-POLICY-CONFIGURED");
  }

  // 7. Technology & Server Banner Leaks
  const server = headers["server"];
  const xPoweredBy = headers["x-powered-by"];
  if (server && /\d+\.\d+/.test(server)) {
    findings.push({
      id: "OWASP-SERVER-VERSION-LEAK",
      title: "Detailed Server Software & Version Disclosure",
      category: "OWASP",
      owaspCategory: "A05:2021-Security Misconfiguration",
      severity: "LOW",
      description: `Server header reveals precise version info: "${server}".`,
      location: `Server: ${server}`,
      impact: "Aids attackers in looking up known CVEs for the exact server version.",
      remediation: "Disable server tokens in Nginx (server_tokens off;) or Apache (ServerTokens Prod).",
    });
  } else {
    passedRules.push("OWASP-SERVER-HEADER-MINIMAL");
  }

  if (xPoweredBy) {
    findings.push({
      id: "OWASP-POWERED-BY-LEAK",
      title: "Technology Stack Disclosed via X-Powered-By",
      category: "OWASP",
      owaspCategory: "A05:2021-Security Misconfiguration",
      severity: "LOW",
      description: `X-Powered-By header discloses underlying backend: "${xPoweredBy}".`,
      location: `X-Powered-By: ${xPoweredBy}`,
      impact: "Assists attackers in targeting language-specific attack vectors.",
      remediation: "Disable header in framework (e.g. app.disable('x-powered-by') in Express, expose_php = Off in php.ini).",
      codeSnippet: `// Express:
app.disable('x-powered-by');

// PHP php.ini:
expose_php = Off`,
    });
  } else {
    passedRules.push("OWASP-NO-POWERED-BY-LEAK");
  }

  // 8. CORS Configuration Check
  const acao = headers["access-control-allow-origin"];
  const acac = headers["access-control-allow-credentials"];
  if (acao === "*" && acac === "true") {
    findings.push({
      id: "OWASP-CORS-WILDCARD-CREDENTIALS",
      title: "Insecure CORS: Wildcard Origin with Credentials",
      category: "OWASP",
      owaspCategory: "A01:2021-Broken Access Control",
      severity: "HIGH",
      description: "Access-Control-Allow-Origin is set to '*' while Allow-Credentials is true.",
      location: "CORS Headers",
      impact: "Cross-origin websites can make authenticated API requests and read private user responses.",
      remediation: "Reflect only trusted origins explicitly instead of using wildcard '*'.",
    });
  }

  // 9. Cookie Security Flags
  const rawSetCookie = res.rawHeaders["set-cookie"];
  if (rawSetCookie) {
    const cookies = Array.isArray(rawSetCookie) ? rawSetCookie : [rawSetCookie];
    for (const cookie of cookies) {
      if (!cookie) continue;
      const lower = cookie.toLowerCase();
      const cookieName = cookie.split("=")[0].trim();

      if (!lower.includes("httponly")) {
        findings.push({
          id: "OWASP-COOKIE-NO-HTTPONLY",
          title: `Cookie "${cookieName}" Missing HttpOnly Flag`,
          category: "OWASP",
          owaspCategory: "A07:2021-Identification & Authentication Failures",
          severity: "MEDIUM",
          description: `The cookie "${cookieName}" can be accessed via document.cookie by client-side JavaScript.`,
          location: `Set-Cookie: ${cookieName}`,
          impact: "If an XSS vulnerability exists, attackers can steal session tokens directly.",
          remediation: "Append '; HttpOnly' to the Set-Cookie header.",
        });
      }
      if (isHttps && !lower.includes("secure")) {
        findings.push({
          id: "OWASP-COOKIE-NO-SECURE",
          title: `Cookie "${cookieName}" Missing Secure Flag`,
          category: "OWASP",
          owaspCategory: "A07:2021-Identification & Authentication Failures",
          severity: "MEDIUM",
          description: `The cookie "${cookieName}" does not specify 'Secure' flag on an HTTPS site.`,
          location: `Set-Cookie: ${cookieName}`,
          impact: "Cookie will be transmitted in plaintext if the user accesses an HTTP URL.",
          remediation: "Append '; Secure' to the Set-Cookie header.",
        });
      }
      if (!lower.includes("samesite")) {
        findings.push({
          id: "OWASP-COOKIE-NO-SAMESITE",
          title: `Cookie "${cookieName}" Missing SameSite Attribute`,
          category: "OWASP",
          owaspCategory: "A01:2021-Broken Access Control",
          severity: "LOW",
          description: `Cookie "${cookieName}" lacks SameSite=Lax or SameSite=Strict.`,
          location: `Set-Cookie: ${cookieName}`,
          impact: "Susceptible to Cross-Site Request Forgery (CSRF).",
          remediation: "Set SameSite=Lax (default for modern flows) or SameSite=Strict.",
        });
      }
    }
  }

  // 10. Sensitive Path Probing (Optional / Deep Scan)
  if (options.probeSensitivePaths) {
    const sensitivePaths = [
      "/.env",
      "/.git/config",
      "/phpinfo.php",
      "/.DS_Store",
      "/wp-config.php.bak",
    ];

    for (const p of sensitivePaths) {
      const probe = await probePath(res.url, p);
      if (probe.exists) {
        findings.push({
          id: "OWASP-EXPOSED-SENSITIVE-FILE",
          title: `Critical File Exposed: ${p}`,
          category: "OWASP",
          owaspCategory: "A05:2021-Security Misconfiguration",
          severity: "CRITICAL",
          description: `The sensitive file ${p} is publicly reachable and returned HTTP ${probe.status}. Snippet: ${probe.snippet || ""}`,
          location: `${res.url}${p}`,
          impact: "Exposes secret credentials, database passwords, or internal repository configuration to the public.",
          remediation: `Configure your web server (Nginx/Apache) to deny access to hidden files and ${p}.`,
          codeSnippet: `// Nginx:
location ~ /\\.(env|git) {
    deny all;
    return 404;
}`,
        });
      }
    }
  }

  // 11. Error Stack Trace / Debug Leaks in Body
  if (res.statusCode >= 400 && res.body) {
    const leakSignatures = [
      { pattern: /fatal error:[^<]+/i, title: "PHP Fatal Error Leak" },
      { pattern: /traceback \(most recent call last\):/i, title: "Python Stack Trace Leak" },
      { pattern: /sqlstate\[\d+\]/i, title: "Database Query Exception Leak" },
      { pattern: /at\s+[\w\.]+\s+\([^\)]+\.js:\d+:\d+\)/i, title: "Node.js Stack Trace Leak" },
      { pattern: /org\.apache\.[a-zA-Z0-9_\.]+/i, title: "Java Stack Trace Leak" },
    ];

    for (const sig of leakSignatures) {
      const match = res.body.match(sig.pattern);
      if (match) {
        findings.push({
          id: "OWASP-DEBUG-ERROR-LEAK",
          title: `Information Disclosure: ${sig.title}`,
          category: "OWASP",
          owaspCategory: "A05:2021-Security Misconfiguration",
          severity: "HIGH",
          description: `Server response leaked internal runtime/database error details: "${match[0].slice(0, 100)}"`,
          location: `HTTP ${res.statusCode} Response Body`,
          impact: "Gives attackers detailed insight into file paths, database structure, and line numbers.",
          remediation: "Disable debug error displays in production and serve generic error pages.",
        });
        break;
      }
    }
  }

  return { findings, passedRules };
}
