import { test } from "node:test";
import assert from "node:assert";
import childProcess from "node:child_process";
import { mkdtempSync, mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobManager } from "../src/jobs/jobManager.js";
import { runScan } from "../src/jobs/worker.js";
import { scanRepository } from "../src/tools/scan.js";
import { getScanStatus } from "../src/tools/status.js";
import { shardHash, type Advisory } from "../src/advisory/db.js";
import { DEFAULT_OPTIONS, ENV } from "../src/constants.js";

delete process.env[ENV.ADVISORY_DB];

const root = realpathSync(mkdtempSync(join(tmpdir(), "jrun-")));
const deps = { pathOptions: { allowedRoots: [root] } };
let n = 0;

const ADV: Advisory = {
  id: "GHSA-test-0001",
  summary: "Prototype pollution",
  severity: [{ type: "CVSS_V3", score: 7.4 }],
  affected: [
    {
      package: { ecosystem: "npm", name: "lodash" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
    },
  ],
};

function makeDb(): string {
  const dir = join(root, `db${n++}`);
  mkdirSync(join(dir, "npm"), { recursive: true });
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString() }));
  writeFileSync(join(dir, "npm", "lodash.json"), JSON.stringify({ contentSha256: shardHash([ADV]), advisories: [ADV] }));
  return dir;
}

function mixedRepo(): string {
  const d = join(root, `mixed${n++}`);
  mkdirSync(join(d, "src"), { recursive: true });
  writeFileSync(join(d, "src", "app.js"), 'const r = eval(userInput);\nres.setHeader("Access-Control-Allow-Origin", "*");\n');
  writeFileSync(join(d, "src", "keys.js"), 'const k = "AKIAABCDEFGHIJKLMNOP";\n');
  writeFileSync(
    join(d, "package-lock.json"),
    JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "node_modules/lodash": { version: "4.17.15" } } }, null, 2) + "\n",
  );
  return d;
}

type Env = { isError?: boolean; structuredContent: Record<string, any> };

async function scan(manager: JobManager, repoPath: string, extra: Record<string, unknown> = {}, options: Record<string, unknown> = {}) {
  const r = (await scanRepository(manager, { repoPath, options: { advisoryDbPath: makeDb(), ...options }, ...extra }, deps)) as Env;
  assert.strictEqual(r.isError, undefined, JSON.stringify(r.structuredContent));
  const job = manager.getJob(r.structuredContent["scanId"] as string);
  assert.ok(job);
  await job.done;
  return job;
}

test("T-11 (F-14) a scan of the no-exec fixture spawns 0 child processes and a default scan performs 0 network calls", async () => {
  const cp = childProcess as unknown as Record<string, unknown>;
  const names = ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"];
  const saved = names.map((k) => [k, cp[k]] as const);
  let spawned = 0;
  for (const k of names) cp[k] = () => { spawned += 1; throw new Error("no child processes"); };
  const orig = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (() => {
    calls += 1;
    return Promise.reject(new Error("no network"));
  }) as typeof fetch;
  try {
    const res = await runScan(
      { repoPath: mixedRepo(), scanners: ["dependency", "secret", "static", "config"], options: DEFAULT_OPTIONS as unknown as Record<string, unknown> },
      () => undefined,
    );
    assert.ok(res.findings.length > 0);
    assert.strictEqual(spawned, 0);
    assert.strictEqual(calls, 0);
  } finally {
    globalThis.fetch = orig;
    for (const [k, v] of saved) cp[k] = v;
  }
});

test("T-06 (F-08) integration: maxFindings=3, strictLimits false => completed, truncated true, 3 findings", async () => {
  const m = new JobManager();
  const job = await scan(m, mixedRepo(), {}, { limits: { maxFindings: 3 } });
  assert.strictEqual(job.state, "completed");
  assert.strictEqual(job.truncated, true);
  assert.strictEqual(job.findings.length, 3);
  assert.strictEqual(job.summary?.truncated, true);
});

test("T-06 (F-08) integration: maxFindings=3, strictLimits true => failed with error E_LIMIT_EXCEEDED", async () => {
  const m = new JobManager();
  const job = await scan(m, mixedRepo(), {}, { limits: { maxFindings: 3 }, strictLimits: true });
  assert.strictEqual(job.state, "failed");
  assert.strictEqual(job.error, "E_LIMIT_EXCEEDED");
  const st = getScanStatus(m, { scanId: job.scanId }) as Env;
  assert.strictEqual(st.structuredContent["state"], "failed");
  assert.strictEqual(st.structuredContent["error"].code, "E_LIMIT_EXCEEDED");
});

test("a mixed repo yields findings from all four scanners (byScanner has dependency, secret, static, config each >= 1)", async () => {
  const m = new JobManager();
  const job = await scan(m, mixedRepo());
  assert.strictEqual(job.state, "completed");
  const by = job.summary?.byScanner ?? {};
  for (const k of ["dependency", "secret", "static", "config"]) assert.ok((by[k] ?? 0) >= 1, `${k}: ${JSON.stringify(by)}`);
  const aws = job.findings.find((f) => f.ruleId === "SEC-AWS-ACCESS-KEY-ID");
  assert.ok(aws);
  assert.ok(!aws.evidence.includes("ABCDEFGHIJKL"));
});

test("progress filesScanned never decreases across polls", async () => {
  const m = new JobManager();
  const repo = join(root, `many${n++}`);
  mkdirSync(repo);
  for (let i = 0; i < 40; i++) writeFileSync(join(repo, `f${i}.txt`), `file ${i}\n`);
  const r = (await scanRepository(m, { repoPath: repo, scanners: ["secret"] }, deps)) as Env;
  const id = r.structuredContent["scanId"] as string;
  let last = 0;
  for (let i = 0; i < 200; i++) {
    const st = getScanStatus(m, { scanId: id }) as Env;
    const f = st.structuredContent["progress"].filesScanned as number;
    assert.ok(f >= last, `${f} < ${last}`);
    last = f;
    if (st.structuredContent["state"] === "completed") break;
    await new Promise((res) => setTimeout(res, 20));
  }
  assert.strictEqual(last, 40);
});
