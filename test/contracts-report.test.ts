import { test } from "node:test";
import assert from "node:assert";
import { validateInput, validateOutput } from "../src/contracts.js";

const SID = "S-3f9a1c2b7d4e-1";
const SUM = {
  total: 0,
  bySeverity: {},
  byScanner: {},
  riskScore: 0,
  riskRating: "none",
  truncated: false,
};

test("generate_report input rejects formats []", () => {
  assert.ok(!validateInput("generate_report", { scanId: SID, formats: [] }).valid);
});

test('generate_report input rejects formats ["pdf"] and accepts ["md","json","sarif"]', () => {
  assert.ok(!validateInput("generate_report", { scanId: SID, formats: ["pdf"] }).valid);
  assert.ok(validateInput("generate_report", { scanId: SID, formats: ["md", "json", "sarif"] }).valid);
});

test("generate_report input rejects an unknown key", () => {
  assert.ok(!validateInput("generate_report", { scanId: SID, foo: true }).valid);
});

test("list_scanners input accepts {} and rejects {x:1}", () => {
  assert.ok(validateInput("list_scanners", {}).valid);
  assert.ok(!validateInput("list_scanners", { x: 1 }).valid);
});

test("a sample list_scanners output validates (required serverVersion, rulesetHash, scanners, advisoryDb, networkAllowed, limits)", () => {
  const lim = { default: 1, min: 1, max: 2 };
  const sample = {
    serverVersion: "0.1.0",
    rulesetHash: "abc",
    scanners: [{ id: "dependency", version: "1", ruleCount: 1, enabledByDefault: true, requiresAdvisoryDb: true }],
    advisoryDb: { present: false },
    networkAllowed: false,
    limits: {
      maxFiles: lim,
      maxFileBytes: lim,
      maxTotalBytes: lim,
      maxFindings: lim,
      timeoutMs: lim,
      getFindingsMax: 200,
      maxRunning: 2,
      maxQueued: 8,
    },
  };
  assert.ok(validateOutput("list_scanners", sample).valid);
  const { serverVersion: _s, ...missing } = sample;
  void _s;
  assert.ok(!validateOutput("list_scanners", missing).valid);
});

test("a sample generate_report output validates (required scanId, outputDir, files, summary, partial)", () => {
  const sample = {
    scanId: SID,
    outputDir: "/tmp/out",
    partial: false,
    summary: SUM,
    files: [{ format: "json", path: "/tmp/out/report.json", bytes: 10, sha256: "a".repeat(64) }],
  };
  assert.ok(validateOutput("generate_report", sample).valid);
  const { partial: _p, ...missing } = sample;
  void _p;
  assert.ok(!validateOutput("generate_report", missing).valid);
});
