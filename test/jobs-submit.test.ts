import { test } from "node:test";
import assert from "node:assert";
import { mkdtempSync, mkdirSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobManager, type StubResult } from "../src/jobs/jobManager.js";
import { scanRepository } from "../src/tools/scan.js";
import { ENV } from "../src/constants.js";

const root = realpathSync(mkdtempSync(join(tmpdir(), "jsub-")));
const deps = { pathOptions: { allowedRoots: [root] } };
let n = 0;
function repo(): string {
  const d = join(root, `r${n++}`);
  mkdirSync(d);
  return d;
}

interface Ctl {
  manager: JobManager;
  finish(i: number): void;
  launched: number;
}

function controlled(): Ctl {
  const resolvers: Array<() => void> = [];
  const ctl: Ctl = {
    launched: 0,
    finish: (i) => resolvers[i]?.(),
    manager: undefined as unknown as JobManager,
  };
  ctl.manager = new JobManager(
    () =>
      new Promise<StubResult>((resolve) => {
        ctl.launched += 1;
        resolvers.push(() => resolve({ filesScanned: 0, threadId: 0, osvCalls: 0 }));
      }),
  );
  return ctl;
}

type Env = { isError?: boolean; structuredContent: Record<string, any> };

async function fill(ctl: Ctl): Promise<string> {
  // 2 running + 8 queued
  const first = repo();
  for (let i = 0; i < 10; i++) {
    const r = (await scanRepository(ctl.manager, { repoPath: i === 0 ? first : repo() }, deps)) as Env;
    assert.strictEqual(r.isError, undefined);
  }
  return first;
}

test("T-05 reuse: with 2 running + 8 queued jobs, an identical request returns reused:true", async () => {
  const ctl = controlled();
  const first = await fill(ctl);
  assert.strictEqual(ctl.launched, 2);
  const r = (await scanRepository(ctl.manager, { repoPath: first }, deps)) as Env;
  assert.strictEqual(r.isError, undefined);
  assert.strictEqual(r.structuredContent["reused"], true);
});

test("T-05 queue full: with 2 running + 8 queued jobs, a new request => E_LIMIT_EXCEEDED", async () => {
  const ctl = controlled();
  await fill(ctl);
  const r = (await scanRepository(ctl.manager, { repoPath: repo() }, deps)) as Env;
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_LIMIT_EXCEEDED");
});

test("T-05 (F-08a) force: identical request with force=true => E_LIMIT_EXCEEDED", async () => {
  const ctl = controlled();
  const first = await fill(ctl);
  const r = (await scanRepository(ctl.manager, { repoPath: first, force: true }, deps)) as Env;
  assert.strictEqual(r.isError, true);
  assert.strictEqual(r.structuredContent["error"].code, "E_LIMIT_EXCEEDED");
  assert.strictEqual(ctl.launched, 2);
});

test("T-11 (F-14) network flag: online=true without VULN_MCP_ALLOW_NETWORK => E_NETWORK_DISABLED", async () => {
  const saved = process.env[ENV.ALLOW_NETWORK];
  delete process.env[ENV.ALLOW_NETWORK];
  const orig = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (() => {
    calls += 1;
    return Promise.reject(new Error("no network"));
  }) as typeof fetch;
  try {
    const ctl = controlled();
    const r = (await scanRepository(ctl.manager, { repoPath: repo(), options: { online: true } }, deps)) as Env;
    assert.strictEqual(r.isError, true);
    assert.strictEqual(r.structuredContent["error"].code, "E_NETWORK_DISABLED");
    assert.strictEqual(calls, 0);
    assert.strictEqual(ctl.launched, 0);
  } finally {
    globalThis.fetch = orig;
    if (saved !== undefined) process.env[ENV.ALLOW_NETWORK] = saved;
  }
});

test("terminal jobs are never reused (same request gets a new scanId)", async () => {
  const ctl = controlled();
  const p = repo();
  const a = (await scanRepository(ctl.manager, { repoPath: p }, deps)) as Env;
  ctl.finish(0);
  const job = (ctl.manager as unknown as { jobs: Map<string, { done: Promise<void> }> }).jobs.get(a.structuredContent["scanId"]);
  await job?.done;
  const b = (await scanRepository(ctl.manager, { repoPath: p }, deps)) as Env;
  assert.strictEqual(b.structuredContent["reused"], false);
  assert.notStrictEqual(b.structuredContent["scanId"], a.structuredContent["scanId"]);
  assert.strictEqual(b.structuredContent["requestKey"], a.structuredContent["requestKey"]);
});

test("identical inputs give identical 64-hex requestKey and scanId S-<requestKey[0:12]>-<counter>", async () => {
  const p = repo();
  const a = (await scanRepository(controlled().manager, { repoPath: p }, deps)) as Env;
  const b = (await scanRepository(controlled().manager, { repoPath: p }, deps)) as Env;
  const key = a.structuredContent["requestKey"] as string;
  assert.match(key, /^[0-9a-f]{64}$/);
  assert.strictEqual(key, b.structuredContent["requestKey"]);
  assert.strictEqual(a.structuredContent["scanId"], `S-${key.slice(0, 12)}-1`);
});
