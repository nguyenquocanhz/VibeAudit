# 🛡️ VibeAudit

> **OWASP Top 10 Security & Web Vibe / UX Quality Auditor**  
> *Available simultaneously as an interactive CLI (`vibe-audit`) and a Model Context Protocol (MCP) Server for Claude Desktop, Cursor, Antigravity, and AI Agents.*

---

## ⚡ Highlights

- **🔒 OWASP Top 10 Live & Codebase Auditing**:
  - Live inspection: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), Clickjacking (X-Frame-Options), MIME Sniffing, Referrer Policy, CORS misconfigurations, Cookie flags (`HttpOnly`, `Secure`, `SameSite`), and server software disclosures.
  - Static AST/regex code scanning: Hardcoded secrets (AWS, GitHub, OpenAI, Google, Slack, Private Keys, DB URIs), dangerous code sinks (`eval()`, `dangerouslySetInnerHTML`), unencrypted HTTP API requests, and unignored `.env` files.
- **✨ Web Vibe & UX Quality (No More "Web Vibe Lỏ")**:
  - **Chromium Dark Mode `<select>` Contrast Guard**: Enforces explicit styling on dropdown `<option>` elements (`background-color` and `color`) to prevent illegible white-on-white text in Chrome/Edge/Brave.
  - **Mobile Ergonomics**: Responsive `<meta name="viewport">` validation and mobile touch target recommendations.
  - **Zero-Flicker & FOUC Prevention**: Detects client-side theme initialization flicker.
  - **SEO & Social Share Preview**: Checks for `<title>`, meta descriptions, and OpenGraph/Twitter card readiness.
  - **Code Hygiene**: Catches leftover `debugger;` breakpoints, production `console.log` statements, and blocking browser `alert()` modals.
- **📊 Unified Scoring & Grading Matrix**:
  - Generates numerical scores (0-100) and letter grades (**A+**, **A**, **B**, **C**, **D**, **F**).
  - Categorized breakdown for Security vs. UX Quality.
- **🛠️ Instant Auto-Remediation**:
  - Ready-to-copy server configs for **Nginx**, **Apache**, **Express.js (Helmet)**, and **PHP**.
  - Drop-in CSS fixes for Dark Mode select contrast.
  - Exportable GitHub Flavored Markdown reports (`--output report.md`).

---

## 🚀 Quick Start (CLI)

Run directly via Node.js or `npx`:

```bash
# Audit a live website or API endpoint
npx vibe-audit --url https://example.com

# Audit a local codebase or repository
npx vibe-audit --dir ./my-project

# Full combined audit with markdown report and auto-fix snippets
npx vibe-audit --url https://api.myweb.com --dir ./src --output audit-report.md --fix
```

### CLI Options

| Flag | Description |
|---|---|
| `-u, --url <url>` | Target live web endpoint or API to audit |
| `-d, --dir <path>` | Target local directory / codebase to scan |
| `-p, --probe` | Probe for sensitive exposed files (`/.env`, `/.git/config`) |
| `-o, --output <file>` | Export full audit findings as Markdown |
| `-j, --json` | Output machine-readable JSON results |
| `--fix` | Print remediation snippets and configuration blocks |

---

## 🔌 MCP Integration (Claude Desktop / Cursor / Antigravity)

VibeAudit implements the standard **Model Context Protocol (v2024-11-05)** over stdio.

### 1. Claude Desktop (`claude_desktop_config.json`)

Add VibeAudit to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vibe-audit": {
      "command": "node",
      "args": [
        "D:\\VibeAudit\\dist\\index.js"
      ]
    }
  }
}
```

### 2. Available MCP Tools

| Tool | Description | Inputs |
|---|---|---|
| `vibe_audit_endpoint` | Audits a live URL for OWASP headers, SSL, CORS, cookies, viewport, and SEO | `{ url: string, probeSensitivePaths?: boolean }` |
| `vibe_audit_codebase` | Scans local codebase for secrets, XSS sinks, dark mode contrast flaw, console leaks | `{ path: string }` |
| `vibe_audit_full` | Runs combined endpoint and codebase audit with unified grading | `{ url?: string, path?: string }` |
| `vibe_quick_check` | Rapid audit returning score, grade, and top issues | `{ url: string }` |
| `vibe_get_remediation` | Returns ready-to-use patch code (Nginx, Apache, Express, PHP, CSS) | `{ type: "nginx" \| "darkmode-select" \| "all" }` |

---

## 🎨 The Chromium Dark Mode Select Rule

On Chromium-based browsers (Google Chrome, Microsoft Edge, Brave, Opera), native `<select>` dropdown options inherit the text `color` from the parent `<select>` (which is white/light in Dark Mode) but defaults to an OS white background. This results in **illegible white text on a white background**.

VibeAudit automatically flags this issue and provides the drop-in fix:

```css
/* Explicit Chromium Dark Mode Option Contrast Fix */
select option,
select.form-control option,
select.form-select option {
  background-color: var(--bg-card, #1e1e1e) !important;
  color: var(--text-primary, #ffffff) !important;
}
```

---

## 🛠️ Development & Building

```bash
# Install dependencies
npm install

# Build CLI and MCP bundles
npm run build

# Run CLI locally
node bin/vibe-audit.js --url https://wrenspec.vietcode.io.vn/api/delete/RemoveUserData
```

---

## 📄 License

MIT © [Nguyen Quoc Anh](https://github.com/nguyenquocanhz)
