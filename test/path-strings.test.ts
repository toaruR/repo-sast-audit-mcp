import { test } from "node:test";
import assert from "node:assert";
import os from "node:os";
import path from "node:path";
import { validateRepoPath } from "../src/security/paths.js";

const root = path.join(os.tmpdir(), "vuln-root");
const opts = { allowedRoots: [root] };
const code = (p: string): string | undefined => {
  try {
    validateRepoPath(p, opts);
  } catch (e) {
    return (e as { code?: string }).code;
  }
  return undefined;
};

test("T-10 (F-16): <root>/../x => E_PATH_TRAVERSAL", () => {
  assert.strictEqual(code(`${root}/../x`), "E_PATH_TRAVERSAL");
});
test("T-10 (F-16): ./repo (relative) => E_INVALID_INPUT", () => {
  assert.strictEqual(code("./repo"), "E_INVALID_INPUT");
});
test("T-10 (F-16): a path containing a NUL char => E_INVALID_INPUT", () => {
  assert.strictEqual(code(`${root}/a\0b`), "E_INVALID_INPUT");
});
test("T-10 (F-16): reserved segments CON and COM1 in any path segment (also <root>/con/x) => E_INVALID_INPUT", () => {
  assert.strictEqual(code(`${root}/con/x`), "E_INVALID_INPUT");
  assert.strictEqual(code(`${root}/a/COM1`), "E_INVALID_INPUT");
  assert.strictEqual(code(`${root}/ok/repo`), undefined);
});
test("path outside SAST_AUDIT_MCP_ALLOWED_ROOTS => E_PATH_TRAVERSAL", () => {
  assert.strictEqual(code(path.join(os.tmpdir(), "other", "repo")), "E_PATH_TRAVERSAL");
});
test("path of PATH_MAX+1 (4097) chars => E_INVALID_INPUT", () => {
  const p = root + "/" + "a".repeat(4097 - root.length - 1);
  assert.strictEqual(p.length, 4097);
  assert.strictEqual(code(p), "E_INVALID_INPUT");
});
