import { test, before } from "node:test";
import assert from "node:assert";
import { mkdirSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobManager } from "../src/jobs/jobManager.js";
import { getFindings } from "../src/tools/getFindings.js";
import { scanRepository } from "../src/tools/scan.js";
import { buildAdvisoryDb } from "./fixtures/advisory-db.js";
import { PLANTED_JS, PLANTED_PY, buildClean, buildPlantedJs, buildPlantedPy, type Planted } from "./fixtures/build.js";

interface Fnd {
  ruleId: string;
  location: { path: string; line: number; column: number };
}
interface Result {
  state: string;
  summary: { total: number; riskScore: number; riskRating: string };
  findings: Fnd[];
}

let root: string;
let dbDir: string;
const manager = new JobManager();

before(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "e2e-det-")));
  dbDir = join(root, "advisory-db");
  mkdirSync(dbDir);
  buildAdvisoryDb(dbDir);
});

async function scan(build: (dir: string) => void, name: string): Promise<Result> {
  const repo = join(root, name);
  mkdirSync(repo);
  build(repo);
  const res = await scanRepository(
    manager,
    { repoPath: repo, waitMs: 30000, options: { advisoryDbPath: dbDir } },
    { pathOptions: { allowedRoots: [root] } },
  );
  assert.ok(!res.isError, JSON.stringify(res.structuredContent));
  const sc = res.structuredContent as { scanId: string; state: string; summary: Result["summary"] };
  assert.strictEqual(sc.state, "completed");
  const f = getFindings(manager, { scanId: sc.scanId, limit: 200 });
  const fc = f.structuredContent as { findings: Fnd[] };
  return { state: sc.state, summary: sc.summary, findings: fc.findings };
}

function tuples(f: readonly { ruleId: string; location: { path: string; line: number } }[]): string[] {
  return f.map((x) => `${x.ruleId}|${x.location.path}|${x.location.line}`).sort();
}

function expected(p: readonly Planted[]): string[] {
  return p.map((x) => `${x.ruleId}|${x.path}|${x.line}`).sort();
}

test("T-01: planted-js yields exactly the 10 listed (ruleId,path,line) tuples and 0 extra", async () => {
  const r = await scan(buildPlantedJs, "js1");
  assert.deepStrictEqual(tuples(r.findings), expected(PLANTED_JS));
  assert.strictEqual(r.findings.length, 10);
});

test("T-01: planted-js riskScore 72 and rating critical", async () => {
  const r = await scan(buildPlantedJs, "js2");
  assert.strictEqual(r.summary.riskScore, 72);
  assert.strictEqual(r.summary.riskRating, "critical");
});

test("T-01: planted-py yields exactly the 9 listed tuples and 0 extra", async () => {
  const r = await scan(buildPlantedPy, "py1");
  assert.deepStrictEqual(tuples(r.findings), expected(PLANTED_PY));
  assert.strictEqual(r.findings.length, 9);
});

test("T-01: planted-py riskScore 80 and rating critical", async () => {
  const r = await scan(buildPlantedPy, "py2");
  assert.strictEqual(r.summary.riskScore, 80);
  assert.strictEqual(r.summary.riskRating, "critical");
});

test("T-01: clean yields 0 findings", async () => {
  const r = await scan(buildClean, "clean1");
  assert.strictEqual(r.findings.length, 0);
});

test("T-01: clean riskScore 0 and rating none", async () => {
  const r = await scan(buildClean, "clean2");
  assert.strictEqual(r.summary.riskScore, 0);
  assert.strictEqual(r.summary.riskRating, "none");
});
