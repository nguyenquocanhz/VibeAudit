import { AuditFinding } from "../types/index.js";
import { HttpResponseData } from "../utils/http.js";

export function auditVibeEndpoint(
  res: HttpResponseData
): { findings: AuditFinding[]; passedRules: string[] } {
  const findings: AuditFinding[] = [];
  const passedRules: string[] = [];

  const html = res.body;

  // Only perform DOM/HTML vibe checks if it's an HTML response
  const isHtml =
    (res.headers["content-type"] && res.headers["content-type"].includes("text/html")) ||
    html.includes("<html") ||
    html.includes("<!DOCTYPE") ||
    html.includes("<head");

  if (!isHtml) {
    passedRules.push("VIBE-NON-HTML-ENDPOINT");
    return { findings, passedRules };
  }

  // 1. Viewport Meta Check (Mobile Responsiveness)
  const hasViewport = /<meta\s+[^>]*name=["']viewport["'][^>]*content=["'][^"']*width=device-width[^"']*["']/i.test(
    html
  );
  if (!hasViewport) {
    findings.push({
      id: "VIBE-VIEWPORT-MISSING",
      title: "Missing or Incomplete Mobile Viewport Meta Tag",
      category: "VIBE",
      severity: "HIGH",
      description:
        "The page is missing `<meta name='viewport' content='width=device-width, initial-scale=1.0'>`. Mobile browsers will render in legacy 980px desktop mode, causing severe visual scale distortion and broken touch vibe.",
      location: "<head>",
      impact: "Broken mobile UX, tiny unreadable fonts, and horizontal page overflow on phones.",
      remediation: "Add standard responsive viewport meta tag inside the <head> element.",
      codeSnippet: `<meta name="viewport" content="width=device-width, initial-scale=1.0" />`,
    });
  } else {
    passedRules.push("VIBE-VIEWPORT-CONFIGURED");
  }

  // 2. SEO & Title Check
  const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
  if (!titleMatch || !titleMatch[1].trim()) {
    findings.push({
      id: "VIBE-TITLE-EMPTY",
      title: "Missing or Empty Page <title> Tag",
      category: "VIBE",
      severity: "MEDIUM",
      description: "Page lacks a descriptive <title> tag.",
      location: "<head><title>",
      impact: "Search engines and social previews will show an empty or untrusted title.",
      remediation: "Add an informative title concisely summarizing the application or page.",
    });
  } else {
    const title = titleMatch[1].trim();
    if (title.toLowerCase().includes("vite + react") || title.toLowerCase().includes("create react app")) {
      findings.push({
        id: "VIBE-TITLE-DEFAULT-BOILERPLATE",
        title: "Default Boilerplate Title Detected",
        category: "VIBE",
        severity: "LOW",
        description: `Page title is still using template placeholder: "${title}".`,
        location: `<title>${title}</title>`,
        impact: "Projects an unpolished, amateur vibe to users and search crawlers.",
        remediation: "Replace with your custom product or service branding.",
      });
    } else {
      passedRules.push("VIBE-TITLE-CUSTOMIZED");
    }
  }

  // 3. Meta Description Check
  const hasMetaDesc = /<meta\s+[^>]*name=["']description["'][^>]*content=["'][^"']+["']/i.test(html);
  if (!hasMetaDesc) {
    findings.push({
      id: "VIBE-META-DESCRIPTION-MISSING",
      title: "Missing Meta Description Tag",
      category: "VIBE",
      severity: "LOW",
      description: "Search engines require <meta name='description' content='...'> for snippet previews.",
      location: "<head>",
      impact: "Lower click-through rates and poor snippet presentation in Google / search engines.",
      remediation: "Add a 150-160 character meta description explaining page content.",
      codeSnippet: `<meta name="description" content="Your crisp application summary here." />`,
    });
  } else {
    passedRules.push("VIBE-META-DESCRIPTION-PRESENT");
  }

  // 4. OpenGraph Social Sharing Tags
  const hasOgTitle = /<meta\s+[^>]*property=["']og:title["']/i.test(html);
  const hasOgImage = /<meta\s+[^>]*property=["']og:image["']/i.test(html);
  if (!hasOgTitle || !hasOgImage) {
    findings.push({
      id: "VIBE-OPENGRAPH-MISSING",
      title: "Incomplete OpenGraph Tags (og:title, og:image)",
      category: "VIBE",
      severity: "LOW",
      description:
        "Page lacks OpenGraph preview tags. Links shared on Discord, Zalo, Telegram, Facebook, and Twitter will appear blank without banners.",
      location: "<head>",
      impact: "Degraded social share vibe; users get plain text links without preview cards.",
      remediation: "Add og:title, og:image, og:description, and twitter:card meta tags.",
      codeSnippet: `<meta property="og:title" content="Your App Title" />\n<meta property="og:description" content="Your App Description" />\n<meta property="og:image" content="https://example.com/banner.png" />\n<meta name="twitter:card" content="summary_large_image" />`,
    });
  } else {
    passedRules.push("VIBE-OPENGRAPH-CONFIGURED");
  }

  // 5. Favicon Check
  const hasFavicon = /<link\s+[^>]*rel=["'](shortcut )?icon["']/i.test(html);
  if (!hasFavicon) {
    findings.push({
      id: "VIBE-FAVICON-MISSING",
      title: "Missing Favicon Link Tag",
      category: "VIBE",
      severity: "LOW",
      description: "No favicon declaration found in HTML head.",
      location: "<head>",
      impact: "Browser tabs display blank placeholder or 404 for /favicon.ico.",
      remediation: "Include `<link rel='icon' type='image/svg+xml' href='/favicon.svg' />` in head.",
    });
  } else {
    passedRules.push("VIBE-FAVICON-PRESENT");
  }

  // 6. HTML Lang Attribute (Accessibility & UX)
  const langMatch = html.match(/<html\s+[^>]*lang=["']([^"']+)["']/i);
  if (!langMatch) {
    findings.push({
      id: "VIBE-HTML-LANG-MISSING",
      title: "Missing lang Attribute on <html> Element",
      category: "ACCESSIBILITY",
      severity: "LOW",
      description: "<html> tag lacks a valid language attribute (e.g. lang='en' or lang='vi').",
      location: "<html>",
      impact: "Screen readers struggle with pronunciation and auto-translation tools misclassify content.",
      remediation: "Specify the primary document language, e.g. <html lang='vi'> or <html lang='en'>.",
    });
  } else {
    passedRules.push("VIBE-HTML-LANG-CONFIGURED");
  }

  // 7. Theme Color Meta (Mobile Status Bar Integration)
  const hasThemeColor = /<meta\s+[^>]*name=["']theme-color["']/i.test(html);
  if (!hasThemeColor) {
    findings.push({
      id: "VIBE-THEME-COLOR-MISSING",
      title: "Missing <meta name='theme-color'> for Mobile Browsers",
      category: "VIBE",
      severity: "INFO",
      description: "Setting theme-color tints the mobile browser's navigation and status bar for a native app feel.",
      location: "<head>",
      impact: "Missed opportunity for seamless native UI blending on iOS Safari and Android Chrome.",
      remediation: "Add `<meta name='theme-color' content='#0f172a' />` to match your dark/light brand palette.",
    });
  } else {
    passedRules.push("VIBE-THEME-COLOR-CONFIGURED");
  }

  // 8. Dark Mode Flash Prevention Check (FOUC)
  const usesDarkTheme =
    html.includes("dark:") ||
    html.includes("theme-dark") ||
    html.includes("class=\"dark\"") ||
    html.includes("color-scheme");
  const hasInlineThemeScript =
    /<script[^>]*>(?:(?!(<\/script>))[\s\S])*localStorage\.(?:getItem|theme)[\s\S]*<\/script>/i.test(
      html.slice(0, Math.min(html.indexOf("</head>"), 8000))
    );

  if (usesDarkTheme && !hasInlineThemeScript && html.includes("localStorage")) {
    findings.push({
      id: "VIBE-DARK-MODE-FOUC-RISK",
      title: "Potential Dark Mode Flash of Unstyled Content (FOUC)",
      category: "VIBE",
      severity: "MEDIUM",
      description:
        "The app supports dark themes via client storage, but lacks an early synchronous inline theme-init script before rendering. Users in dark mode may experience a glaring white flash upon reload.",
      location: "<head>",
      impact: "Jarrying visual flicker causing poor perception of app quality.",
      remediation:
        "Inject a tiny blocking inline script at the top of <head> that reads the saved theme and sets document.documentElement.classList.add('dark') before CSS renders.",
      codeSnippet: `<script>
  (function() {
    try {
      var theme = localStorage.getItem('theme');
      if (theme === 'dark' || (!theme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
        document.documentElement.classList.add('dark');
      }
    } catch(e) {}
  })();
</script>`,
    });
  }

  return { findings, passedRules };
}
