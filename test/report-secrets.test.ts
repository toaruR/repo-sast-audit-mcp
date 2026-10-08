import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DEFAULT_OPTIONS, ENV, LEAK_SUBSTR, REDACT_PREFIX } from "../src/constants.js";
import { shardHash, type Advisory } from "../src/advisory/db.js";
import { runScan } from "../src/jobs/worker.js";
import { assertNoSecrets } from "../src/security/assertNoSecrets.js";
import { generateReport, type ReportSource } from "../src/tools/generateReport.js";

delete process.env[ENV.ADVISORY_DB];
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vuln-rs-")));
let n = 0;
const AKIA = "AKIAQ7XK2MZP5RTW9HDN";
const API_SECRET = "kJ8dP2xQ9vL4mZ7wR1tY6uN3";

const ADV: Advisory = {
  id: "GHSA-test-0001",
  severity: [{ type: "CVSS_V3", score: 7.4 }],
  affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
};
const db = path.join(base, "db");
fs.mkdirSync(path.join(db, "npm"), { recursive: true });
fs.writeFileSync(path.join(db, "manifest.json"), JSON.stringify({ schemaVersion: 1, generatedAt: "2026-09-01T00:00:00Z" }));
fs.writeFileSync(path.join(db, "npm", "lodash.json"), JSON.stringify({ contentSha256: shardHash([ADV]), advisories: [ADV] }));

function tree(files: Record<string, string>): string {
  const d = path.join(base, `t${n++}`);
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(d, rel)), { recursive: true });
    fs.writeFileSync(path.join(d, rel), text);
  }
  return d;
}

const LOCK = JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "node_modules/lodash": { version: "4.17.15" } } }, null, 2) + "\n";
const planted = (): string =>
  tree({
    "src/app.js": 'const r = eval(userInput);\nres.setHeader("Access-Control-Allow-Origin", "*");\n',
    ".env": `NODE_ENV=production\nAWS_ACCESS_KEY_ID=${AKIA}\n`,
    Dockerfile: "FROM node:20\n",
    "package-lock.json": LOCK,
  });

async function source(repo: string): Promise<ReportSource> {
  const res = await runScan(
    { repoPath: repo, scanners: ["dependency", "secret", "static", "config"], options: DEFAULT_OPTIONS as unknown as Record<string, unknown>, dbPath: db },
    () => undefined,
  );
  return {
    getJob: () =>
      ({ scanId: "S-0123456789ab-1", repoPath: repo, state: "completed", findings: res.findings, warnings: res.warnings, truncated: res.truncated }) as unknown as ReturnType<ReportSource["getJob"]>,
  };
}

const deps = { pathOptions: { allowedRoots: [base] }, outputRoot: path.join(base, "out") };
type Env = { isError?: boolean; structuredContent: Record<string, any> };
const ALL = { scanId: "S-0123456789ab-1", formats: ["md", "json", "sarif"] };

/** True when a LEAK_SUBSTR-char substring of raw past its first REDACT_PREFIX chars occurs in text. */
function leaks(text: string, raw: string): boolean {
  for (let i = REDACT_PREFIX; i + LEAK_SUBSTR <= raw.length; i++) {
    if (text.includes(raw.slice(i, i + LEAK_SUBSTR))) return true;
  }
  return false;
}

const read = (r: Env, name: string): string => fs.readFileSync(path.join(r.structuredContent["outputDir"], name), "utf8");

test("T-13 (F-13) report.md: no 5-char substring of the AKIA key after its first 4 chars", async () => {
  const src = await source(planted());
  const r = generateReport(src, ALL, deps) as unknown as Env;
  assert.strictEqual(r.isError, undefined, JSON.stringify(r.structuredContent));
  const md = read(r, "report.md");
  assert.ok(md.includes("SEC-AWS-ACCESS-KEY-ID"));
  assert.ok(!leaks(md, AKIA));
});

test("T-13 (F-13) report.json: no 5-char substring of the AKIA key after its first 4 chars", async () => {
  const r = generateReport(await source(planted()), ALL, deps) as unknown as Env;
  const json = read(r, "report.json");
  assert.ok(json.includes("SEC-AWS-ACCESS-KEY-ID"));
  assert.ok(!leaks(json, AKIA));
});

test("T-13 (F-13) report.sarif.json: no 5-char substring of the AKIA key after its first 4 chars", async () => {
  const r = generateReport(await source(planted()), ALL, deps) as unknown as Env;
  assert.ok(!leaks(read(r, "report.sarif.json"), AKIA));
});

test("T-13 (F-13) captured logs: no recorded string contains a 5-char substring of the AKIA key after its first 4 chars", async () => {
  const src = await source(planted());
  const rec: string[] = [];
  const saved = { err: process.stderr.write, out: process.stdout.write, log: console.log, warn: console.warn, error: console.error };
  process.stderr.write = ((s: unknown) => (rec.push(String(s)), true)) as typeof process.stderr.write;
  console.log = (...a: unknown[]) => void rec.push(a.map(String).join(" "));
  console.warn = (...a: unknown[]) => void rec.push(a.map(String).join(" "));
  console.error = (...a: unknown[]) => void rec.push(a.map(String).join(" "));
  let r: Env;
  try {
    r = generateReport(src, ALL, deps) as unknown as Env;
  } finally {
    process.stderr.write = saved.err;
    console.log = saved.log;
    console.warn = saved.warn;
    console.error = saved.error;
  }
  assert.strictEqual(r.isError, undefined);
  for (const s of rec) assert.ok(!leaks(s, AKIA));
});

test("T-13 (F-13) API_SECRET: none of the three report files contains a 5-char substring of that value", async () => {
  const repo = tree({ "config.py": `API_SECRET = "${API_SECRET}"\n`, "package-lock.json": LOCK });
  const src = await source(repo);
  assert.ok(src.getJob("x")!.findings.some((f) => f.ruleId === "SEC-GENERIC-HIGH-ENTROPY"));
  const r = generateReport(src, ALL, deps) as unknown as Env;
  assert.strictEqual(r.isError, undefined, JSON.stringify(r.structuredContent));
  for (const f of ["report.md", "report.json", "report.sarif.json"]) assert.ok(!leaks(read(r, f), API_SECRET), f);
});

test("assertNoSecrets is invoked once per generated file (spy count 3 for 3 formats)", async () => {
  const src = await source(planted());
  const seen: string[] = [];
  const r = generateReport(src, ALL, {
    ...deps,
    assertNoSecrets: (t: string) => {
      seen.push(t);
      assertNoSecrets(t);
    },
  }) as unknown as Env;
  assert.strictEqual(r.isError, undefined);
  assert.strictEqual(seen.length, 3);
});

test("a secret in a generated file makes generate_report fail with E_INTERNAL and writes nothing", async () => {
  const src = await source(planted());
  const bad: ReportSource = {
    getJob: (id) => {
      const j = src.getJob(id)!;
      return { ...j, findings: j.findings.map((f, i) => (i === 0 ? { ...f, message: `leak ${AKIA}` } : f)) };
    },
  };
  const out = path.join(base, "out-bad");
  const r = generateReport(bad, ALL, { ...deps, outputRoot: out }) as unknown as Env;
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_INTERNAL");
  assert.ok(!r.structuredContent["error"].message.includes(AKIA));
  assert.ok(!fs.existsSync(out));
});
