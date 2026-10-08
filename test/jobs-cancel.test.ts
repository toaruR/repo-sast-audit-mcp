import { test } from "node:test";
import assert from "node:assert";
import { mkdtempSync, mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobManager, type LaunchResult } from "../src/jobs/jobManager.js";
import { runScan } from "../src/jobs/worker.js";
import { scanRepository } from "../src/tools/scan.js";
import { cancelScan, getScanStatus } from "../src/tools/status.js";
import { CANCEL_DRAIN_MS, DEFAULT_OPTIONS, ENV } from "../src/constants.js";

delete process.env[ENV.ADVISORY_DB];

const root = realpathSync(mkdtempSync(join(tmpdir(), "jcan-")));
const deps = { pathOptions: { allowedRoots: [root] } };
let n = 0;

function smallRepo(): string {
  const d = join(root, `s${n++}`);
  mkdirSync(d);
  writeFileSync(join(d, "a.txt"), "hello\n");
  return d;
}

let big: string | undefined;
/** Large tree (many files across many directories) so a real scan outlasts the 1000 ms minimum timeout. */
function bigRepo(): string {
  if (big) return big;
  const d = join(root, "big");
  mkdirSync(d);
  const line = "const value = compute(input) + 1; // filler line to give the scanners some work\n".repeat(20);
  for (let i = 0; i < 100; i++) {
    const sub = join(d, `d${i}`);
    mkdirSync(sub);
    for (let j = 0; j < 100; j++) writeFileSync(join(sub, `f${j}.js`), line);
  }
  big = d;
  return d;
}

type Env = { isError?: boolean; structuredContent: Record<string, any> };

const hang = (): Promise<LaunchResult> => new Promise<LaunchResult>(() => undefined);

test("T-08 (F-09): real timeoutMs=1000 on a large tree => state timed_out, complete false, durationMs <= 1000+CANCEL_DRAIN_MS (4000)", async () => {
  const m = new JobManager();
  const r = (await scanRepository(m, { repoPath: bigRepo(), scanners: ["static"], options: { limits: { timeoutMs: 1000 } } }, deps)) as Env;
  assert.strictEqual(r.isError, undefined, JSON.stringify(r.structuredContent));
  const id = r.structuredContent["scanId"] as string;
  const job = m.getJob(id);
  assert.ok(job);
  await job.done;
  const st = getScanStatus(m, { scanId: id }) as Env;
  assert.strictEqual(st.structuredContent["state"], "timed_out");
  assert.strictEqual(st.structuredContent["error"].code, "E_TIMEOUT");
  assert.ok((st.structuredContent["durationMs"] as number) <= 1000 + CANCEL_DRAIN_MS, String(st.structuredContent["durationMs"]));
});

test("T-08 (F-09a): cancel_scan on a running job (real worker, large tree) returns cancelRequested true, and the job reaches cancelled with E_CANCELLED within CANCEL_DRAIN_MS (3000)", async () => {
  const m = new JobManager();
  const r = (await scanRepository(m, { repoPath: bigRepo(), scanners: ["static"] }, deps)) as Env;
  const id = r.structuredContent["scanId"] as string;
  const job = m.getJob(id);
  assert.ok(job);
  await new Promise((res) => setTimeout(res, 200));
  assert.strictEqual(job.state, "running");
  const t0 = Date.now();
  const c = cancelScan(m, { scanId: id }) as Env;
  assert.strictEqual(c.structuredContent["cancelRequested"], true);
  await job.done;
  assert.ok(Date.now() - t0 <= CANCEL_DRAIN_MS, `took ${Date.now() - t0}`);
  const st = getScanStatus(m, { scanId: id }) as Env;
  assert.strictEqual(st.structuredContent["state"], "cancelled");
  assert.strictEqual(st.structuredContent["error"].code, "E_CANCELLED");
  assert.strictEqual(st.structuredContent["cancelRequested"], true);
});

test("cancel_scan on a terminal job is a no-op answered before transition", async () => {
  const m = new JobManager();
  const r = (await scanRepository(m, { repoPath: smallRepo(), scanners: ["secret"] }, deps)) as Env;
  const id = r.structuredContent["scanId"] as string;
  await m.getJob(id)?.done;
  assert.strictEqual(m.getJob(id)?.state, "completed");
  const c = cancelScan(m, { scanId: id }) as Env;
  assert.strictEqual(c.isError, undefined);
  assert.strictEqual(c.structuredContent["state"], "completed");
  assert.strictEqual(c.structuredContent["cancelRequested"], false);
  const unknown = cancelScan(m, { scanId: "S-000000000000-1" }) as Env;
  assert.strictEqual(unknown.structuredContent["error"].code, "E_NOT_FOUND");
});

test("cancel_scan on a queued job returns state cancelled immediately", async () => {
  const m = new JobManager(hang);
  const ids: string[] = [];
  for (let i = 0; i < 3; i++) {
    const r = (await scanRepository(m, { repoPath: smallRepo(), scanners: ["secret"] }, deps)) as Env;
    ids.push(r.structuredContent["scanId"] as string);
  }
  assert.strictEqual(m.getJob(ids[2] as string)?.state, "queued");
  const c = cancelScan(m, { scanId: ids[2] }) as Env;
  assert.strictEqual(c.structuredContent["state"], "cancelled");
  await m.getJob(ids[2] as string)?.done;
  const st = getScanStatus(m, { scanId: ids[2] }) as Env;
  assert.strictEqual(st.structuredContent["error"].code, "E_CANCELLED");
});

test("abort propagates: the worker observes signal.aborted after cancel", async () => {
  let seen: AbortSignal | undefined;
  const m = new JobManager((_p, _s, _o, signal) => {
    seen = signal;
    return new Promise<LaunchResult>((resolve) => signal?.addEventListener("abort", () => resolve({ aborted: true })));
  });
  const r = (await scanRepository(m, { repoPath: smallRepo(), scanners: ["secret"] }, deps)) as Env;
  const id = r.structuredContent["scanId"] as string;
  assert.strictEqual(seen?.aborted, false);
  cancelScan(m, { scanId: id });
  assert.strictEqual(seen?.aborted, true);
  await m.getJob(id)?.done;
  assert.strictEqual(m.getJob(id)?.state, "cancelled");
  // The real worker pipeline stops on the shared abort flag.
  const flag = new SharedArrayBuffer(4);
  Atomics.store(new Int32Array(flag), 0, 1);
  const res = await runScan(
    { repoPath: smallRepo(), scanners: ["secret"], options: DEFAULT_OPTIONS as unknown as Record<string, unknown>, abortFlag: flag },
    () => undefined,
  );
  assert.strictEqual(res.aborted, true);
});

test("waitMs=0 returns a non-terminal state without blocking", async () => {
  const m = new JobManager(hang);
  const t0 = Date.now();
  const r = (await scanRepository(m, { repoPath: smallRepo(), scanners: ["secret"], waitMs: 0 }, deps)) as Env;
  assert.ok(Date.now() - t0 < 500);
  assert.ok(["queued", "running"].includes(r.structuredContent["state"]));
});
