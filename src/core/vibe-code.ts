import { AuditFinding } from "../types/index.js";
import { ScannedFile } from "../utils/file-scanner.js";

export async function auditVibeCodebase(
  files: ScannedFile[]
): Promise<{ findings: AuditFinding[]; passedRules: string[] }> {
  const findings: AuditFinding[] = [];
  const passedRules: string[] = [];

  let hasDarkModeSelect = false;
  let hasOptionExplicitStyling = false;
  let selectLocation = "";

  for (const file of files) {
    const isStyleFile = [".css", ".scss", ".sass", ".less"].includes(file.extension);
    const isComponentFile = [".jsx", ".tsx", ".vue", ".svelte", ".html"].includes(file.extension);
    const isScriptFile = [".js", ".ts", ".mjs", ".cjs"].includes(file.extension);

    // 1. Scan CSS/Styles for Chromium Dark Mode Select Contrast Rule
    if (isStyleFile || isComponentFile) {
      const content = file.content;

      // Look for select dark mode styling
      const darkModeSelectMatch =
        /(?:\.dark|\[data-theme=["']dark["']\]|@media\s*\([^)]*prefers-color-scheme:\s*dark[^)]*\))[\s\S]{0,300}select\b/i.test(
          content
        ) ||
        /select[^{]*\{[^}]*(?:background|bg-|color)[^}]*\}/i.test(content) &&
          (content.includes(".dark") || content.includes("prefers-color-scheme"));

      if (darkModeSelectMatch) {
        hasDarkModeSelect = true;
        selectLocation = file.relativePath;
      }

      // Look for explicit option styling
      const optionStyled =
        /select\s+(?:>\s*)?option\s*\{[^}]*background(?:-color)?\s*:[^}]*color\s*:[^}]*\}/i.test(
          content
        ) ||
        /select\.form-control\s+option\s*\{[^}]*background(?:-color)?\s*:[^}]*color\s*:[^}]*\}/i.test(
          content
        ) ||
        /select\s+option\b[^\{]*\{[^}]*background/i.test(content);

      if (optionStyled) {
        hasOptionExplicitStyling = true;
      }
    }

    // 2. Scan lines for Console Leaks, Debugger, and Legacy Modals
    if (isScriptFile || isComponentFile) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;
        const trimmed = line.trim();

        if (trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) {
          continue;
        }

        // Leftover console.log in non-test files
        if (
          /\bconsole\.(log|debug|info)\s*\(/.test(trimmed) &&
          !file.relativePath.includes("test") &&
          !file.relativePath.includes("spec") &&
          !file.relativePath.includes("cli")
        ) {
          findings.push({
            id: "VIBE-CONSOLE-LOG-LEAK",
            title: "Leftover Debug Logging (console.log)",
            category: "CODE_HYGIENE",
            severity: "LOW",
            description: `Active debug log statement left in production code at ${file.relativePath}:${lineNum}.`,
            location: `${file.relativePath}:${lineNum}`,
            evidence: trimmed.slice(0, 70),
            impact: "Pollutes browser console and may leak runtime state or user IDs.",
            remediation: "Remove console.log or wrap with environment check (e.g. if (process.env.NODE_ENV !== 'production')).",
          });
        }

        // Leftover debugger; statement
        const isDebuggerRegex = /\/.*debugger.*\/|\.test\(|regex:/.test(trimmed);
        if (/^\s*debugger\s*;?$/.test(trimmed) || (/\bdebugger\s*;/.test(trimmed) && !isDebuggerRegex)) {
          findings.push({
            id: "VIBE-DEBUGGER-STATEMENT",
            title: "Active debugger; Statement in Code",
            category: "CODE_HYGIENE",
            severity: "HIGH",
            description: `Direct debugger breakpoint statement found in ${file.relativePath}:${lineNum}.`,
            location: `${file.relativePath}:${lineNum}`,
            evidence: trimmed,
            impact: "Will pause execution abruptly for any user who opens DevTools.",
            remediation: "Delete all debugger statements before deployment.",
          });
        }

        // Legacy blocking alert() / confirm() / prompt()
        const isModalRegex = /\/.*alert.*\/|\.test\(|regex:/.test(trimmed);
        if (/\b(?:window\.)?(alert|confirm|prompt)\s*\([^)]*\)/.test(trimmed) && !isModalRegex) {
          findings.push({
            id: "VIBE-LEGACY-BROWSER-MODAL",
            title: "Legacy Blocking Browser Dialog (alert/confirm/prompt)",
            category: "VIBE",
            severity: "MEDIUM",
            description: `Synchronous browser dialog (${trimmed.match(/\b(alert|confirm|prompt)/)?.[0]}) used in ${file.relativePath}:${lineNum}.`,
            location: `${file.relativePath}:${lineNum}`,
            evidence: trimmed.slice(0, 70),
            impact: "Freezes browser main thread, breaks mobile viewports, and delivers an outdated 1990s user experience.",
            remediation: "Replace with modern native `<dialog>` or non-blocking toast/modal component.",
            codeSnippet: `// Modern native dialog replacement:
const dialog = document.querySelector('dialog');
dialog.showModal();`,
          });
        }

        // Destructive focus outline removal without replacement
        if (/outline\s*:\s*(?:none|0)\s*(?:!important)?\s*;/i.test(trimmed) && !file.content.includes(":focus-visible")) {
          findings.push({
            id: "VIBE-ACCESSIBILITY-OUTLINE-REMOVED",
            title: "Focus Outline Removed Without :focus-visible Alternative",
            category: "ACCESSIBILITY",
            severity: "MEDIUM",
            description: `CSS removes focus outline in ${file.relativePath}:${lineNum} without providing an accessible :focus-visible ring.`,
            location: `${file.relativePath}:${lineNum}`,
            evidence: trimmed,
            impact: "Keyboard navigation becomes completely invisible for disabled and power users.",
            remediation: "Use `:focus-visible` with a high-contrast outline or ring.",
            codeSnippet: `:focus-visible { outline: 2px solid var(--accent-color, #3b82f6); outline-offset: 2px; }`,
          });
        }
      }
    }
  }

  // 3. Evaluate Dark Mode Select Option Contrast Rule
  if (hasDarkModeSelect && !hasOptionExplicitStyling) {
    findings.push({
      id: "VIBE-DARKMODE-SELECT-UNSTYLED-OPTIONS",
      title: "Chromium Dark Mode <select> Option White-on-White Contrast Flaw",
      category: "VIBE",
      severity: "HIGH",
      description:
        "Dark Mode styling was detected on `<select>` elements, but `<option>` elements lack explicit `background-color` and `color`. On Chromium-based browsers (Chrome, Edge, Brave, Opera), the dropdown list inherits white text from the parent but retains a default white background, rendering dropdown options unreadable white-on-white text!",
      location: selectLocation || "Styles",
      impact: "Severe usability breakdown in dark mode: users cannot read dropdown options when expanded.",
      remediation:
        "Explicitly style the `<option>` elements with matching dark background and light text.",
      codeSnippet: `/* Explicit Chromium Dark Mode Option Contrast Fix */
select option,
select.form-control option {
  background-color: var(--bg-card, #1e1e1e);
  color: var(--text-primary, #ffffff);
}`,
      autoFixAvailable: true,
    });
  } else if (hasOptionExplicitStyling) {
    passedRules.push("VIBE-DARKMODE-SELECT-CONTRAST-COMPLIANT");
  }

  if (findings.length === 0) {
    passedRules.push("VIBE-CODEBASE-CLEAN");
  }

  return { findings, passedRules };
}
