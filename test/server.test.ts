import { test } from "node:test";
import assert from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../src/server.js";

const BAD_RULES = {
  rules: [
    {
      id: "BAD-RULE-001",
      title: "bad",
      languages: ["any"],
      pattern: "abc",
      severity: "low",
      confidence: "low",
      cwe: "CWE-1",
      tests: { shouldMatch: ["xyz"], shouldNotMatch: ["qqq"] },
    },
  ],
};

function badRuleFile(): string {
  const dir = mkdtempSync(join(tmpdir(), "badrule-"));
  const f = join(dir, "rules.json");
  writeFileSync(f, JSON.stringify(BAD_RULES));
  return f;
}

interface Exited {
  code: number | null;
  stderr: string;
}

function runBadRules(): Promise<Exited> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", "tsx", "src/index.ts", badRuleFile()], { stdio: ["pipe", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    const timer = setTimeout(() => child.kill(), 20000);
    child.once("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, stderr });
    });
  });
}

test("T-27 (F-14a) bad rule exit code", async () => {
  const r = await runBadRules();
  assert.strictEqual(r.code, 2);
});

test("T-27 (F-14a) stderr", async () => {
  const r = await runBadRules();
  assert.match(r.stderr, /E_RULE_INVALID/);
});

test("T-27 (F-14a) no tools", async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["--import", "tsx", "src/index.ts", badRuleFile()],
  });
  const client = new Client({ name: "t", version: "0" });
  let tools: unknown;
  try {
    await client.connect(transport);
    tools = (await client.listTools()).tools;
  } catch {
    tools = undefined;
  }
  try {
    await client.close();
  } catch {
    /* already gone */
  }
  assert.strictEqual(tools, undefined);
});

test("tools/list over stdio returns exactly the 6 tools", async () => {
  const transport = new StdioClientTransport({ command: process.execPath, args: ["--import", "tsx", "src/index.ts"] });
  const client = new Client({ name: "t", version: "0" });
  await client.connect(transport);
  try {
    const names = (await client.listTools()).tools.map((t) => t.name).sort();
    assert.deepStrictEqual(names, ["cancel_scan", "generate_report", "get_findings", "get_scan_status", "list_scanners", "scan_repository"]);
  } finally {
    await client.close();
  }
});

test("unexpected exception inside a handler returns an E_INTERNAL envelope", async () => {
  const server = createServer(undefined, {
    log: () => undefined,
    handlers: {
      list_scanners: () => {
        throw new Error("boom /secret/path");
      },
    },
  });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "t", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    const res = await client.callTool({ name: "list_scanners", arguments: {} });
    assert.strictEqual(res.isError, true);
    const err = (res.structuredContent as { error: { code: string; message: string } }).error;
    assert.strictEqual(err.code, "E_INTERNAL");
    assert.ok(!err.message.includes("boom"));
  } finally {
    await client.close();
  }
});

test("logs contain only ruleId, counts and relative paths (no absolute path or evidence)", async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "logrepo-")));
  const repo = join(root, "myrepo");
  mkdirSync(repo);
  const key = "AKIAZ7QW3RT5YU2MNB4K";
  writeFileSync(join(repo, ".env"), `# c\nAWS_KEY=${key}\n`);
  const lines: string[] = [];
  const server = createServer(undefined, { log: (l) => lines.push(l) });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "t", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  const prev = process.env["SAST_AUDIT_MCP_ALLOWED_ROOTS"];
  process.env["SAST_AUDIT_MCP_ALLOWED_ROOTS"] = root;
  try {
    const scan = await client.callTool({
      name: "scan_repository",
      arguments: { repoPath: repo, scanners: ["secret"], waitMs: 15000 },
    });
    const sc = scan.structuredContent as { scanId: string; state: string };
    assert.strictEqual(sc.state, "completed");
    const f = await client.callTool({ name: "get_findings", arguments: { scanId: sc.scanId } });
    const total = (f.structuredContent as { total: number }).total;
    assert.ok(total >= 1);
  } finally {
    if (prev === undefined) delete process.env["SAST_AUDIT_MCP_ALLOWED_ROOTS"];
    else process.env["SAST_AUDIT_MCP_ALLOWED_ROOTS"] = prev;
    await client.close();
  }
  const all = lines.join("\n");
  assert.ok(all.includes("finding=SEC-AWS-ACCESS-KEY-ID@.env"), all);
  assert.ok(!all.includes(root));
  assert.ok(!all.includes(basename(root)));
  assert.ok(!all.includes("AKIA"));
  assert.ok(!all.includes(key.slice(4, 12)));
});
