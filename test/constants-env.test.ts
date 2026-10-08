import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { DEFAULT_OPTIONS, ENV, TOOL_DEFAULTS } from "../src/constants.js";

test("env names", () => {
  assert.deepStrictEqual(
    Object.values(ENV).sort(),
    [
      "SAST_AUDIT_MCP_ALLOWED_ROOTS",
      "SAST_AUDIT_MCP_OUTPUT_ROOT",
      "SAST_AUDIT_MCP_ALLOW_NETWORK",
      "SAST_AUDIT_MCP_FIXED_TIME",
      "SAST_AUDIT_MCP_DB_STALE_DAYS",
      "SAST_AUDIT_MCP_ADVISORY_DB",
    ].sort(),
  );
});

test("option defaults", () => {
  // limits are covered by constants-limits.test.ts
  const { limits: _limits, ...rest } = DEFAULT_OPTIONS;
  assert.deepStrictEqual(rest, {
    strictLimits: false,
    online: false,
    symlinkPolicy: "skip",
    respectGitignore: true,
    includeGlobs: [],
    excludeGlobs: [],
  });
});

test("tool defaults", () => {
  assert.deepStrictEqual(TOOL_DEFAULTS, {
    force: false,
    getFindings: { limit: 50, includeEvidence: true },
    generateReport: { formats: ["md", "json"], allowWriteInsideTarget: false, allowPartial: false, includeEvidence: true },
  });
});

test("env hygiene", () => {
  const hits: string[] = [];
  const walk = (dir: string): void => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.posix.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (fs.readFileSync(p, "utf8").includes("process.env")) hits.push(p);
    }
  };
  walk("src");
  assert.deepStrictEqual(hits.sort(), ["src/constants.ts"]);
});
