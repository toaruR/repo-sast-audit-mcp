import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Bundled assets (rules/, schemas/) live at the package root. Resolved by walking up to package.json
// so the same code works from src/ (tsx) and dist/src/ (tsc output).
function findPackageRoot(start: string): string {
  for (let dir = start; ; ) {
    if (fs.existsSync(path.join(dir, "package.json"))) return dir;
    const up = path.dirname(dir);
    if (up === dir) throw new Error("package root (package.json) not found");
    dir = up;
  }
}

export const PACKAGE_ROOT = findPackageRoot(path.dirname(fileURLToPath(import.meta.url)));

export function assetPath(...segments: string[]): string {
  return path.join(PACKAGE_ROOT, ...segments);
}
