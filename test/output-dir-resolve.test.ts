import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { validateOutputDir } from "../src/security/paths.js";

const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vuln-or-")));
const repo = path.join(base, "root", "repo");
fs.mkdirSync(repo, { recursive: true });
const outRoot = path.join(base, "out");
const scanId = "S-0123456789ab-1";
const opts = { allowedRoots: [path.join(base, "root")], outputRoot: outRoot, scanId };

const code = (o: Parameters<typeof validateOutputDir>[1]): string | undefined => {
  try {
    validateOutputDir(repo, o);
  } catch (e) {
    return (e as { code?: string }).code;
  }
  return undefined;
};

test("no outputDir resolves to SAST_AUDIT_MCP_OUTPUT_ROOT/<scanId>", () => {
  const saved = process.env.SAST_AUDIT_MCP_OUTPUT_ROOT;
  process.env.SAST_AUDIT_MCP_OUTPUT_ROOT = outRoot;
  try {
    const r = validateOutputDir(repo, { allowedRoots: opts.allowedRoots, scanId });
    assert.strictEqual(r, path.join(outRoot, scanId));
  } finally {
    if (saved === undefined) delete process.env.SAST_AUDIT_MCP_OUTPUT_ROOT;
    else process.env.SAST_AUDIT_MCP_OUTPUT_ROOT = saved;
  }
});
test("allowWriteInsideTarget=true without outputDir resolves to <repo>/.sast-audit/", () => {
  assert.strictEqual(validateOutputDir(repo, { ...opts, allowWriteInsideTarget: true }), path.join(repo, ".sast-audit"));
});
test("explicit outputDir inside the target is accepted when allowWriteInsideTarget=true", () => {
  const o = path.join(repo, "reports");
  assert.strictEqual(validateOutputDir(repo, { ...opts, outputDir: o, allowWriteInsideTarget: true }), o);
});
test("outputDir outside the allowed roots => E_PATH_TRAVERSAL", () => {
  assert.strictEqual(code({ ...opts, outputDir: path.join(base, "elsewhere") }), "E_PATH_TRAVERSAL");
});
test("unreadable outputDir => E_PERMISSION_DENIED before any write (T-23 F-07b)", () => {
  fs.mkdirSync(outRoot, { recursive: true });
  const denied = (): never => {
    throw Object.assign(new Error("denied"), { code: "EACCES" });
  };
  assert.strictEqual(code({ ...opts, outputDir: outRoot, opendirSync: denied }), "E_PERMISSION_DENIED");
  assert.deepStrictEqual(fs.readdirSync(outRoot), []);
});
