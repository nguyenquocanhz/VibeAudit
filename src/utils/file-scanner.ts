import * as fs from "fs";
import * as path from "path";

export interface ScannedFile {
  relativePath: string;
  absolutePath: string;
  extension: string;
  content: string;
  lines: string[];
}

const DEFAULT_IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  ".next",
  ".nuxt",
  ".output",
  "vendor",
  "coverage",
  ".vscode",
  ".idea",
  "target",
  "bin",
  "obj",
]);

const ALLOWED_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".php",
  ".py",
  ".rb",
  ".go",
  ".java",
  ".css",
  ".scss",
  ".sass",
  ".less",
  ".html",
  ".htm",
  ".vue",
  ".svelte",
  ".json",
  ".yaml",
  ".yml",
  ".env",
  ".gitignore",
  ".htaccess",
]);

const MAX_FILE_SIZE_BYTES = 1024 * 512; // 512 KB per file

export async function scanDirectoryFiles(
  rootDir: string,
  options: { skipNodeModules?: boolean } = {}
): Promise<ScannedFile[]> {
  const results: ScannedFile[] = [];

  async function walk(currentDir: string): Promise<void> {
    let entries: fs.Dirent[];
    try {
      entries = await fs.promises.readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = path.relative(rootDir, fullPath);

      if (entry.isDirectory()) {
        if (DEFAULT_IGNORE_DIRS.has(entry.name)) {
          continue;
        }
        await walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        const baseName = entry.name.toLowerCase();

        // Also accept .env files (which have no ext or ext is .env)
        const isEnvFile = baseName.startsWith(".env");
        if (!ALLOWED_EXTENSIONS.has(ext) && !isEnvFile && baseName !== ".gitignore") {
          continue;
        }

        try {
          const stat = await fs.promises.stat(fullPath);
          if (stat.size > MAX_FILE_SIZE_BYTES) {
            continue; // Skip large bundles
          }

          const content = await fs.promises.readFile(fullPath, "utf-8");
          results.push({
            relativePath: relPath.replace(/\\/g, "/"),
            absolutePath: fullPath,
            extension: ext || (isEnvFile ? ".env" : ""),
            content,
            lines: content.split(/\r?\n/),
          });
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  await walk(rootDir);
  return results;
}
