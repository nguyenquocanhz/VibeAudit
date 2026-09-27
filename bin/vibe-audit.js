#!/usr/bin/env node

import("../dist/cli.js").catch((err) => {
  console.error("Failed to run vibe-audit:", err);
  process.exit(1);
});
