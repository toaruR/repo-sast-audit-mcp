import { test } from "node:test";
import assert from "node:assert";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAjv } from "../src/contracts.js";
import { DEFAULT_OPTIONS, ENV } from "../src/constants.js";
import { shardHash, type Advisory } from "../src/advisory/db.js";
import { buildSummary } from "../src/jobs/jobManager.js";
import { runScan } from "../src/jobs/worker.js";
import { renderJson, renderMarkdown, type ReportInput } from "../src/report/render.js";

delete process.env[ENV.ADVISORY_DB];
const root = realpathSync(mkdtempSync(join(tmpdir(), "vuln-rr-")));
let n = 0;

const ADV: Advisory = {
  id: "GHSA-test-0001",
  summary: "Prototype pollution",
  severity: [{ type: "CVSS_V3", score: 7.4 }],
  affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
};

function makeDb(): string {
  const dir = join(root, `db${n++}`);
  mkdirSync(join(dir, "npm"), { recursive: true });
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ schemaVersion: 1, generatedAt: "2026-09-01T00:00:00Z" }));
  writeFileSync(join(dir, "npm", "lodash.json"), JSON.stringify({ contentSha256: shardHash([ADV]), advisories: [ADV] }));
  return dir;
}

/** planted-js-like tree; eol "\r\n" gives the CRLF copy. */
export function plantedJs(eol: string): string {
  const d = join(root, `planted${n++}`);
  mkdirSync(join(d, "src"), { recursive: true });
  const w = (rel: string, lines: string[]): void => writeFileSync(join(d, rel), lines.join(eol) + eol);
  w("src/app.js", ['const r = eval(userInput);', 'res.setHeader("Access-Control-Allow-Origin", "*");', 'exec("ls " + req.query.dir);']);
  w(".env", ["NODE_ENV=production", "AWS_KEY=AKIAABCDEFGHIJKLMNOP"]);
  w("Dockerfile", ["FROM node:20", "COPY . /app"]);
  w("package-lock.json", [
    "{",
    '  "name": "x",',
    '  "lockfileVersion": 3,',
    '  "packages": {',
    '    "node_modules/lodash": { "version": "4.17.15" }',
    "  }",
    "}",
  ]);
  return d;
}

async function input(repo: string, db: string, scanId: string, generatedAt: string): Promise<ReportInput> {
  const res = await runScan(
    { repoPath: repo, scanners: ["dependency", "secret", "static", "config"], options: DEFAULT_OPTIONS as unknown as Record<string, unknown>, dbPath: db },
    () => undefined,
  );
  return {
    scanId,
    rulesetHash: "r".repeat(64),
    generatedAt,
    state: "completed",
    partial: false,
    summary: buildSummary(res.findings, res.truncated),
    findings: res.findings,
    warnings: res.warnings,
  };
}

const REPORT_SCHEMA = {
  type: "object",
  required: ["schemaVersion", "meta", "summary", "findings", "warnings"],
  properties: {
    schemaVersion: { const: "1.0" },
    meta: {
      type: "object",
      required: ["scanId", "rulesetHash", "generatedAt", "state", "partial"],
      properties: {
        scanId: { $ref: "d#/Sid" },
        rulesetHash: { type: "string" },
        generatedAt: { type: "string" },
        state: { $ref: "d#/St" },
        partial: { type: "boolean" },
      },
    },
    summary: { $ref: "d#/Sum" },
    findings: { type: "array", items: { $ref: "d#/Fnd" } },
    warnings: { type: "array", items: { $ref: "d#/Wrn" } },
  },
};

const strip = (json: string): unknown => {
  const o = JSON.parse(json) as { meta: Record<string, unknown>; repoRealPath?: unknown };
  delete o.meta["generatedAt"];
  delete o.meta["scanId"];
  delete o["repoRealPath"];
  return o;
};

const db = makeDb();
const opts = { includeEvidence: true };

test("report.json validates against the section 7 schema", async () => {
  const inp = await input(plantedJs("\n"), db, "S-0123456789ab-1", "2026-10-01T00:00:00.000Z");
  assert.ok(inp.findings.length > 0);
  const validate = createAjv().compile(REPORT_SCHEMA);
  const doc: { meta: { partial: boolean }; findings: unknown[] } = JSON.parse(renderJson(inp, opts));
  assert.ok(validate(doc), JSON.stringify(validate.errors));
  assert.strictEqual(doc.meta.partial, false);
  assert.strictEqual(doc.findings.length, inp.findings.length);
});

test("report.md contains every finding id", async () => {
  const inp = await input(plantedJs("\n"), db, "S-0123456789ab-1", "2026-10-01T00:00:00.000Z");
  const md = renderMarkdown(inp, opts);
  for (const f of inp.findings) assert.ok(md.includes(f.id), f.id);
  assert.ok(!md.includes("\r"));
});

test("T-12: two scan+report runs of the planted-js tree give identical report.json after deleting the fields generatedAt, scanId and repoRealPath from both", async () => {
  const a = await input(plantedJs("\n"), db, "S-0123456789ab-1", "2026-10-01T00:00:00.000Z");
  const b = await input(plantedJs("\n"), db, "S-0123456789ab-2", "2026-10-02T00:00:00.000Z");
  assert.deepStrictEqual(strip(renderJson(a, opts)), strip(renderJson(b, opts)));
});

test("T-12: report.md of those two runs is byte-identical", async () => {
  const a = await input(plantedJs("\n"), db, "S-0123456789ab-1", "2026-10-01T00:00:00.000Z");
  const b = await input(plantedJs("\n"), db, "S-0123456789ab-2", "2026-10-02T00:00:00.000Z");
  assert.strictEqual(renderMarkdown(a, opts), renderMarkdown(b, opts));
});

test("T-12: a CRLF copy of the planted-js tree (every LF replaced by CRLF) gives a report.json identical to the LF run after deleting generatedAt, scanId and repoRealPath from both", async () => {
  const lf = await input(plantedJs("\n"), db, "S-0123456789ab-1", "2026-10-01T00:00:00.000Z");
  const crlf = await input(plantedJs("\r\n"), db, "S-0123456789ab-2", "2026-10-02T00:00:00.000Z");
  assert.deepStrictEqual(strip(renderJson(crlf, opts)), strip(renderJson(lf, opts)));
});

test("includeEvidence=false omits evidence from report.json findings", async () => {
  const inp = await input(plantedJs("\n"), db, "S-0123456789ab-1", "2026-10-01T00:00:00.000Z");
  const full = JSON.parse(renderJson(inp, { includeEvidence: true })).findings as Array<{ evidence: string }>;
  assert.ok(full.some((f) => f.evidence.length > 0));
  const doc = JSON.parse(renderJson(inp, { includeEvidence: false }));
  for (const f of doc.findings as Array<{ evidence: string }>) assert.strictEqual(f.evidence, "");
  assert.ok(createAjv().compile(REPORT_SCHEMA)(doc));
  assert.ok(!renderMarkdown(inp, { includeEvidence: false }).includes("- Evidence:"));
});
