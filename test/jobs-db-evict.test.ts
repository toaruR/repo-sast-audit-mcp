import { test } from "node:test";
import assert from "node:assert";
import { mkdtempSync, mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobManager, type StubResult } from "../src/jobs/jobManager.js";
import { scanRepository } from "../src/tools/scan.js";
import { getScanStatus } from "../src/tools/status.js";
import { validateOutput } from "../src/contracts.js";
import { ENV, JOB_KEEP } from "../src/constants.js";

delete process.env[ENV.ADVISORY_DB];

const root = realpathSync(mkdtempSync(join(tmpdir(), "jdb-")));
const deps = { pathOptions: { allowedRoots: [root] } };
let n = 0;
function repo(): string {
  const d = join(root, `r${n++}`);
  mkdirSync(d);
  return d;
}

const instant = () => Promise.resolve<StubResult>({ filesScanned: 0, threadId: 0, osvCalls: 0 });

type Env = { isError?: boolean; structuredContent: Record<string, any> };

test("T-22 (F-06): no DB and scanners omitted => submit warnings hold W_ADVISORY_DB_MISSING count 1", async () => {
  const m = new JobManager(instant);
  const r = (await scanRepository(m, { repoPath: repo() }, deps)) as Env;
  assert.strictEqual(r.isError, undefined);
  const w = (r.structuredContent["warnings"] as Array<{ code: string; count: number }>).filter((x) => x.code === "W_ADVISORY_DB_MISSING");
  assert.strictEqual(w.length, 1);
  assert.strictEqual(w[0]?.count, 1);
});

test("T-22 (F-06a): scanners=[dependency] with no DB => E_ADVISORY_DB_MISSING", async () => {
  const m = new JobManager(instant);
  const r = (await scanRepository(m, { repoPath: repo(), scanners: ["dependency"] }, deps)) as Env;
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_ADVISORY_DB_MISSING");
});

test("T-22 (F-06a): broken manifest.json => E_ADVISORY_DB_INVALID", async () => {
  const db = mkdtempSync(join(tmpdir(), "jdbm-"));
  writeFileSync(join(db, "manifest.json"), "{not json");
  const m = new JobManager(instant);
  const r = (await scanRepository(m, { repoPath: repo(), scanners: ["dependency"], options: { advisoryDbPath: db } }, deps)) as Env;
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_ADVISORY_DB_INVALID");
});

test("T-29 (F-19): unknown scanId S-000000000000-1 => E_NOT_FOUND with retryable false", () => {
  const r = getScanStatus(new JobManager(instant), { scanId: "S-000000000000-1" }) as Env;
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_NOT_FOUND");
  assert.strictEqual(r.structuredContent["error"].retryable, false);
});

test("T-29 (F-19): the oldest scanId after JOB_KEEP+1 (21) finished scans => E_NOT_FOUND with retryable false", async () => {
  const m = new JobManager(instant);
  const ids: string[] = [];
  for (let i = 0; i < JOB_KEEP + 1; i++) {
    const r = (await scanRepository(m, { repoPath: repo(), scanners: ["secret"] }, deps)) as Env;
    ids.push(r.structuredContent["scanId"]);
    await m.getJob(ids[i] as string)?.done;
  }
  const oldest = getScanStatus(m, { scanId: ids[0] }) as Env;
  assert.strictEqual(oldest.isError, true);
  assert.strictEqual(oldest.structuredContent["error"].code, "E_NOT_FOUND");
  assert.strictEqual(oldest.structuredContent["error"].retryable, false);
  const newest = getScanStatus(m, { scanId: ids[JOB_KEEP] }) as Env;
  assert.strictEqual(newest.isError, undefined);
  assert.strictEqual(newest.structuredContent["state"], "completed");
  assert.ok(validateOutput("get_scan_status", newest.structuredContent).valid);
});

test("generation starts at 0 and increases by 1 per findings commit", async () => {
  let release: () => void = () => undefined;
  const m = new JobManager(() => new Promise<StubResult>((res) => { release = () => res({ filesScanned: 0, threadId: 0, osvCalls: 0 }); }));
  const r = (await scanRepository(m, { repoPath: repo(), scanners: ["secret"] }, deps)) as Env;
  const id = r.structuredContent["scanId"] as string;
  assert.strictEqual(m.getJob(id)?.generation, 0);
  assert.strictEqual(m.commitFindings(id), 1);
  assert.strictEqual(m.commitFindings(id), 2);
  release();
  await m.getJob(id)?.done;
  assert.strictEqual(m.commitFindings(id), 2);
});
