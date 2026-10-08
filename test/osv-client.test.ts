import { test } from "node:test";
import assert from "node:assert";
import { createOsvClient } from "../src/net/osvClient.js";

function fake() {
  const bodies: string[] = [];
  return {
    bodies,
    transport: async (b: string) => {
      bodies.push(b);
      return { vulns: [] };
    },
  };
}
const enabled = () => true;
const lodash = { ecosystem: "npm", name: "lodash", version: "4.17.20" };

test("request body JSON keys equal exactly", async () => {
  const f = fake();
  await createOsvClient({ transport: f.transport, networkAllowed: enabled }).query([lodash]);
  assert.deepStrictEqual(Object.keys(JSON.parse(f.bodies[0]!)).sort(), ["ecosystem", "name", "version"]);
});

test("extra input fields (for example path, line) never appear in the request body", async () => {
  const f = fake();
  const pkg = { ...lodash, path: "secret/dir/package-lock.json", line: 7 };
  await createOsvClient({ transport: f.transport, networkAllowed: enabled }).query([pkg]);
  assert.ok(!f.bodies[0]!.includes("path"));
  assert.ok(!f.bodies[0]!.includes("line"));
  assert.ok(!f.bodies[0]!.includes("secret/dir"));
});

test("network disabled by default", async () => {
  const saved = process.env.SAST_AUDIT_MCP_ALLOW_NETWORK;
  delete process.env.SAST_AUDIT_MCP_ALLOW_NETWORK;
  try {
    const f = fake();
    await assert.rejects(createOsvClient({ transport: f.transport }).query([lodash]), (e: { code?: string }) => e.code === "E_NETWORK_DISABLED");
  } finally {
    if (saved !== undefined) process.env.SAST_AUDIT_MCP_ALLOW_NETWORK = saved;
  }
});

test("no transport call when disabled", async () => {
  const saved = process.env.SAST_AUDIT_MCP_ALLOW_NETWORK;
  delete process.env.SAST_AUDIT_MCP_ALLOW_NETWORK;
  try {
    const f = fake();
    const c = createOsvClient({ transport: f.transport });
    await assert.rejects(c.query([lodash]));
    assert.strictEqual(f.bodies.length, 0);
  } finally {
    if (saved !== undefined) process.env.SAST_AUDIT_MCP_ALLOW_NETWORK = saved;
  }
});

test("one call per package when enabled", async () => {
  const saved = process.env.SAST_AUDIT_MCP_ALLOW_NETWORK;
  process.env.SAST_AUDIT_MCP_ALLOW_NETWORK = "1";
  try {
    const f = fake();
    const pkgs = ["a", "b", "c", "d"].map((n) => ({ ecosystem: "npm", name: n, version: "1.0.0" }));
    await createOsvClient({ transport: f.transport }).query(pkgs);
    assert.strictEqual(f.bodies.length, pkgs.length);
  } finally {
    if (saved === undefined) delete process.env.SAST_AUDIT_MCP_ALLOW_NETWORK;
    else process.env.SAST_AUDIT_MCP_ALLOW_NETWORK = saved;
  }
});
