import { test } from "node:test";
import assert from "node:assert";
import { threadId } from "node:worker_threads";
import { spawn } from "node:child_process";
import { mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

function tempRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), "skel-"));
  writeFileSync(join(dir, "a.txt"), "hello");
  return dir;
}

function connect(): { client: Client; transport: StdioClientTransport } {
  const transport = new StdioClientTransport({ command: process.execPath, args: ["--import", "tsx", "src/index.ts"], env: { VULN_MCP_ALLOWED_ROOTS: realpathSync(tmpdir()) } });
  const client = new Client({ name: "t", version: "0" });
  return { client, transport };
}

test("skeleton: tools/list over stdio", async () => {
  const { client, transport } = connect();
  await client.connect(transport);
  try {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    assert.ok(names.includes("scan_repository"));
    assert.ok(names.includes("get_scan_status"));
  } finally {
    await client.close();
  }
});

test("skeleton: scan then poll", async () => {
  const { client, transport } = connect();
  await client.connect(transport);
  try {
    const res = await client.callTool({ name: "scan_repository", arguments: { repoPath: tempRepo() } });
    const sc = res.structuredContent as { scanId: string; state: string };
    assert.match(sc.scanId, /^S-[0-9a-f]{12}-[0-9]+$/);
    assert.ok(["queued", "running", "completed"].includes(sc.state));
    let last: { state: string; progress: { filesScanned: number } } | undefined;
    for (let i = 0; i < 50; i++) {
      const st = await client.callTool({ name: "get_scan_status", arguments: { scanId: sc.scanId } });
      last = st.structuredContent as typeof last;
      if (last?.state === "completed") break;
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.strictEqual(last?.state, "completed");
    assert.strictEqual(last?.progress.filesScanned, 1);
  } finally {
    await client.close();
  }
});

test("skeleton: stdin close ends the server", async () => {
  const child = spawn(process.execPath, ["--import", "tsx", "src/index.ts"], { stdio: ["pipe", "pipe", "inherit"] });
  await new Promise((r) => setTimeout(r, 1500));
  const exited = new Promise<number | null>((resolve) => child.once("exit", (code) => resolve(code)));
  child.stdin.end();
  const code = await Promise.race([exited, new Promise<string>((r) => setTimeout(() => r("timeout"), 2000))]);
  if (code === "timeout") child.kill();
  assert.strictEqual(code, 0);
});

test("skeleton: real scan runs in a worker thread distinct from main", async () => {
  const { JobManager } = await import("../src/jobs/jobManager.js");
  const m = new JobManager();
  const job = m.submit(tempRepo());
  await job.done;
  assert.strictEqual(job.state, "completed");
  assert.ok(job.stubResult);
  assert.notStrictEqual(job.stubResult.threadId, threadId);
  const { getScanStatus } = await import("../src/tools/status.js");
  assert.ok(!JSON.stringify(await getScanStatus(m, { scanId: job.scanId })).includes("stubResult"));
});
