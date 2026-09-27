import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    cli: "src/cli.ts",
  },
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  shims: true,
  target: "node18",
  banner: {
    js: "// VibeAudit - OWASP Security & Web Vibe Quality Auditor\n",
  },
});
