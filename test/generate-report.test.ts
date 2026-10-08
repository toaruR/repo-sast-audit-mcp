import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { validateOutput } from "../src/contracts.js";
import type { Finding } from "../src/findings/identity.js";
import { generateReport, type ReportSource } from "../src/tools/generateReport.js";

const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vuln-gr-")));
const repo = path.join(base, "repo");
fs.mkdirSync(path.join(repo, "src"), { recursive: true });
fs.writeFileSync(path.join(repo, "src", "a.js"), "x");
const outRoot = path.join(base, "out");
const deps = { pathOptions: { allowedRoots: [base] }, outputRoot: outRoot };

const FINDING: Finding = {
  id: "F-0123456789abcdef",
  ruleId: "STA-JS-EVAL-001",
  scanner: "static",
  title: "Use of eval() on dynamic code",
  severity: "high",
  confidence: "medium",
  cwe: ["CWE-95"],
  location: { path: "src/a.js", line: 1, column: 1 },
  evidence: "const r = eval(x);",
  message: "m",
  remediation: "r",
  fingerprint: "a".repeat(32),
  occurrence: 1,
};

const SID = "S-0123456789ab-1";
function source(state: string): ReportSource {
  return {
    getJob: (id) =>
      id === SID
        ? ({ scanId: SID, repoPath: repo, state, findings: [FINDING], warnings: [], truncated: false } as unknown as ReturnType<ReportSource["getJob"]>)
        : undefined,
  };
}

type Env = { isError?: boolean; structuredContent: Record<string, any> };
const run = (state: string, args: Record<string, unknown> = {}, d = deps): Env =>
  generateReport(source(state), { scanId: SID, ...args }, d) as unknown as Env;
const listing = (d: string): string[] => (fs.existsSync(d) ? fs.readdirSync(d).sort() : []);

test("T-30 (F-18): running job => E_SCAN_NOT_COMPLETE with retryable true", () => {
  const r = run("running");
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_SCAN_NOT_COMPLETE");
  assert.strictEqual(r.structuredContent["error"].retryable, true);
});

test("T-30 (F-18): timed_out job with allowPartial false => E_SCAN_NOT_COMPLETE", () => {
  const r = run("timed_out");
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_SCAN_NOT_COMPLETE");
  assert.strictEqual(listing(path.join(outRoot, SID)).length, 0);
});

test("T-30 (F-18): timed_out job with allowPartial true => files length 2 and partial true", () => {
  const r = run("timed_out", { allowPartial: true });
  assert.strictEqual(r.isError, undefined, JSON.stringify(r.structuredContent));
  assert.strictEqual(r.structuredContent["files"].length, 2);
  assert.strictEqual(r.structuredContent["partial"], true);
  const doc = JSON.parse(fs.readFileSync(path.join(outRoot, SID, "report.json"), "utf8"));
  assert.strictEqual(doc.meta.partial, true);
  assert.strictEqual(doc.meta.state, "timed_out");
});

test("default formats write report.md and report.json only", () => {
  const r = run("completed");
  assert.strictEqual(r.isError, undefined, JSON.stringify(r.structuredContent));
  assert.strictEqual(r.structuredContent["partial"], false);
  const out = r.structuredContent["outputDir"] as string;
  assert.deepStrictEqual(listing(out), ["report.json", "report.md"]);
  assert.deepStrictEqual(r.structuredContent["files"].map((f: { format: string }) => f.format), ["md", "json"]);
  assert.ok(validateOutput("generate_report", r.structuredContent).valid);
});

test("sarif is written only on request", () => {
  const r = run("completed", { formats: ["sarif", "json"] });
  assert.deepStrictEqual(r.structuredContent["files"].map((f: { format: string }) => f.format), ["json", "sarif"]);
});

test("unknown scanId: generate_report {scanId:\"S-000000000000-9\"} => isError true and structuredContent.error.code === \"E_NOT_FOUND\"", () => {
  const r = generateReport(source("completed"), { scanId: "S-000000000000-9" }, deps) as unknown as Env;
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_NOT_FOUND");
});

test("invalid input: unknown key => E_INVALID_INPUT", () => {
  const r = generateReport(source("completed"), { scanId: SID, foo: 1 }, deps) as unknown as Env;
  assert.strictEqual(r.structuredContent["error"].code, "E_INVALID_INPUT");
});

test("section 11 E_OUTPUT_DIR_UNSAFE row: outputDir inside target => E_OUTPUT_DIR_UNSAFE and no file written", () => {
  const inside = path.join(repo, "reports");
  const r = run("completed", { outputDir: inside });
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_OUTPUT_DIR_UNSAFE");
  assert.strictEqual(fs.existsSync(inside), false);
  assert.deepStrictEqual(fs.readdirSync(repo), ["src"]);
});
