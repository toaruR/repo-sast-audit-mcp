import { test, before } from "node:test";
import assert from "node:assert";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { mkdirSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PERF_TARGET_S } from "../src/constants.js";
import { JobManager } from "../src/jobs/jobManager.js";
import { getFindings } from "../src/tools/getFindings.js";
import { scanRepository } from "../src/tools/scan.js";
import { buildAdvisoryDb } from "./fixtures/advisory-db.js";
import { buildPlantedJs, buildPlantedPy } from "./fixtures/build.js";

interface Fnd {
  ruleId: string;
  evidence: string;
  location: { path: string; line: number; column: number };
}
interface Scanned {
  findings: Fnd[];
  byScanner: Record<string, number>;
  elapsedMs: number;
}

let root: string;
let dbDir: string;
let seq = 0;
const manager = new JobManager();

before(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "e2e-prop-")));
  dbDir = join(root, "advisory-db");
  mkdirSync(dbDir);
  buildAdvisoryDb(dbDir);
});

async function scan(build: (dir: string) => void): Promise<Scanned> {
  const repo = join(root, `repo${seq++}`);
  mkdirSync(repo);
  build(repo);
  const t0 = Date.now();
  const res = await scanRepository(
    manager,
    { repoPath: repo, waitMs: 30000, options: { advisoryDbPath: dbDir } },
    { pathOptions: { allowedRoots: [root] } },
  );
  assert.ok(!res.isError, JSON.stringify(res.structuredContent));
  const sc = res.structuredContent as { scanId: string; state: string; summary: { byScanner: Record<string, number> } };
  const elapsedMs = Date.now() - t0;
  assert.strictEqual(sc.state, "completed");
  const f = getFindings(manager, { scanId: sc.scanId, limit: 200 });
  return { findings: (f.structuredContent as { findings: Fnd[] }).findings, byScanner: sc.summary.byScanner, elapsedMs };
}

test("SEC-AWS-ACCESS-KEY-ID found at .env:2:19 with evidence \"AKIA****[REDACTED len=20]\"", async () => {
  const r = await scan(buildPlantedJs);
  const f = r.findings.find((x) => x.ruleId === "SEC-AWS-ACCESS-KEY-ID");
  assert.ok(f);
  assert.deepStrictEqual(f.location, { path: ".env", line: 2, column: 19 });
  assert.strictEqual(f.evidence, "AKIA****[REDACTED len=20]");
});

test("SEC-PRIVATE-KEY found at keys/test.pem:1 and evidence has no key body", async () => {
  const r = await scan(buildPlantedPy);
  const f = r.findings.find((x) => x.ruleId === "SEC-PRIVATE-KEY");
  assert.ok(f);
  assert.strictEqual(f.location.path, "keys/test.pem");
  assert.strictEqual(f.location.line, 1);
  assert.ok(!f.evidence.includes("MIIBVQIBADANBgkqhkiG9w0BAQEFAASC"));
  assert.ok(!f.evidence.includes("pL9wHc2xYyJ1sD5k"));
});

test("G2: two sequential identical scans produce byte-identical findings JSON", async () => {
  const a = await scan(buildPlantedJs);
  const b = await scan(buildPlantedJs);
  assert.strictEqual(JSON.stringify(a.findings), JSON.stringify(b.findings));
  assert.ok(a.findings.length > 0);
});

test("G4: a default scan performs 0 network calls", async () => {
  let calls = 0;
  const saved = {
    fetch: globalThis.fetch,
    http: http.request,
    https: https.request,
    connect: net.connect,
  };
  const spy = (): never => {
    calls++;
    throw new Error("network call attempted");
  };
  globalThis.fetch = spy as unknown as typeof fetch;
  http.request = spy as unknown as typeof http.request;
  https.request = spy as unknown as typeof https.request;
  net.connect = spy as unknown as typeof net.connect;
  try {
    const r = await scan(buildPlantedJs);
    assert.ok(r.findings.length > 0);
  } finally {
    globalThis.fetch = saved.fetch;
    http.request = saved.http;
    https.request = saved.https;
    net.connect = saved.connect;
  }
  assert.strictEqual(calls, 0);
});

test("G5: a scan of planted-js finishes within PERF_TARGET_S (20 s)", async () => {
  const r = await scan(buildPlantedJs);
  assert.ok(r.elapsedMs <= PERF_TARGET_S * 1000, `took ${r.elapsedMs} ms`);
});

test("G1: one scan_repository call runs all 4 scanners", async () => {
  const r = await scan(buildPlantedJs);
  for (const s of ["dependency", "secret", "static", "config"]) {
    assert.ok((r.byScanner[s] ?? 0) >= 1, `scanner ${s} produced no finding`);
  }
});

