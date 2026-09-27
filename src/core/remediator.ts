export interface SecurityHeadersSnippet {
  server: string;
  filename: string;
  config: string;
}

export function generateSecurityHeadersConfig(): Record<string, SecurityHeadersSnippet> {
  return {
    nginx: {
      server: "Nginx",
      filename: "nginx.conf / site-available",
      config: `# VibeAudit OWASP Security Headers for Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:;" always;
server_tokens off;`,
    },
    apache: {
      server: "Apache (.htaccess)",
      filename: ".htaccess",
      config: `# VibeAudit OWASP Security Headers for Apache
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
</IfModule>
ServerSignature Off`,
    },
    express: {
      server: "Node.js (Express with Helmet)",
      filename: "server.js / app.ts",
      config: `// npm install helmet
import helmet from 'helmet';
import express from 'express';

const app = express();
app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  })
);`,
    },
    php: {
      server: "PHP (Native header calls)",
      filename: "config.php / index.php",
      config: `<?php
// VibeAudit OWASP Security Headers for PHP
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: SAMEORIGIN");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
header_remove("X-Powered-By");
?>`,
    },
  };
}

export function generateDarkModeSelectCssFix(): string {
  return `/* ==========================================================================
   VibeAudit: Chromium Dark Mode Select Contrast Rule
   Fixes illegible white-on-white text in Chromium dropdowns (Chrome, Edge, Brave)
   ========================================================================== */
select option,
select.form-control option,
select.form-select option {
  background-color: var(--bg-card, #1e1e1e) !important;
  color: var(--text-primary, #f8fafc) !important;
}

@media (prefers-color-scheme: dark) {
  select option {
    background-color: #1e1e1e;
    color: #f8fafc;
  }
}
`;
}

export function generateHtmlHeadBoilerplate(appName: string = "Modern Web App"): string {
  return `<!-- VibeAudit Recommended Responsive & Social <head> Setup -->
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="color-scheme" content="light dark" />
<meta name="theme-color" content="#0f172a" />
<title>${appName}</title>
<meta name="description" content="High performance, secure web application." />

<!-- OpenGraph / Social Share Vibe -->
<meta property="og:title" content="${appName}" />
<meta property="og:description" content="High performance, secure web application." />
<meta property="og:type" content="website" />
<meta property="og:image" content="/og-banner.png" />
<meta name="twitter:card" content="summary_large_image" />

<!-- Favicon -->
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
<link rel="apple-touch-icon" href="/apple-touch-icon.png" />
`;
}
