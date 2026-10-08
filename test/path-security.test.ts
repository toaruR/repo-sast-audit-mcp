import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { validateRepoDir } from "../src/security/paths.js";

const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vuln-ps-")));
const root = path.join(base, "root");
const outside = path.join(base, "outside");
fs.mkdirSync(path.join(root, "repo"), { recursive: true });
fs.mkdirSync(outside);
fs.writeFileSync(path.join(root, "file.txt"), "x");
fs.writeFileSync(path.join(root, "repo", "a.txt"), "a");
const opts = { allowedRoots: [root] };

const code = (p: string, o: Parameters<typeof validateRepoDir>[1] = opts): string | undefined => {
  try {
    validateRepoDir(p, o);
  } catch (e) {
    return (e as { code?: string }).code;
  }
  return undefined;
};

function treeHash(dir: string): string {
  const h = crypto.createHash("sha256");
  const walk = (d: string): void => {
    for (const n of fs.readdirSync(d).sort()) {
      const p = path.join(d, n);
      const st = fs.lstatSync(p);
      h.update(`${path.relative(dir, p)}|${st.isDirectory() ? "d" : st.isSymbolicLink() ? "l" : "f"}|`);
      if (st.isDirectory()) walk(p);
      else if (st.isFile()) h.update(fs.readFileSync(p));
    }
  };
  walk(dir);
  return h.digest("hex");
}

test("missing path => E_NOT_FOUND", () => {
  assert.strictEqual(code(path.join(root, "nope")), "E_NOT_FOUND");
});
test("path that is a regular file (not a directory) => E_NOT_FOUND", () => {
  assert.strictEqual(code(path.join(root, "file.txt")), "E_NOT_FOUND");
});
test("a valid directory returns its realpath", () => {
  assert.strictEqual(validateRepoDir(path.join(root, "repo"), opts), path.join(root, "repo"));
});
test("a symlink inside the root pointing outside the allowed roots => E_PATH_TRAVERSAL (judged by realpath)", () => {
  const link = path.join(root, "escape");
  fs.symlinkSync(outside, link, "junction");
  assert.strictEqual(code(link), "E_PATH_TRAVERSAL");
});
const denied = (): never => {
  throw Object.assign(new Error("denied"), { code: "EACCES" });
};
test("unreadable repoPath => E_PERMISSION_DENIED (T-23 F-07b)", () => {
  assert.strictEqual(code(path.join(root, "repo"), { ...opts, opendirSync: denied }), "E_PERMISSION_DENIED");
});
test("no read or write occurs after E_PERMISSION_DENIED (fs spy call count 0)", () => {
  const names = ["readdirSync", "readFileSync", "writeFileSync", "mkdirSync", "appendFileSync", "openSync"] as const;
  let calls = 0;
  const orig: Record<string, unknown> = {};
  const f = fs as unknown as Record<string, unknown>;
  assert.strictEqual(code(path.join(root, "repo"), { ...opts, opendirSync: denied }), "E_PERMISSION_DENIED");
  for (const n of names) {
    orig[n] = f[n];
    f[n] = (...a: unknown[]) => {
      calls++;
      return (orig[n] as (...x: unknown[]) => unknown)(...a);
    };
  }
  try {
    // spies installed after the denial: the denial path itself must not have touched them; re-run to count.
    assert.strictEqual(code(path.join(root, "repo"), { ...opts, opendirSync: denied }), "E_PERMISSION_DENIED");
  } finally {
    for (const n of names) f[n] = orig[n];
  }
  assert.strictEqual(calls, 0);
});
test("validation performs no filesystem mutation (tree hash identical before and after)", () => {
  const before = treeHash(base);
  code(path.join(root, "repo"));
  code(path.join(root, "nope"));
  code(path.join(root, "file.txt"));
  code(path.join(root, "escape"));
  assert.strictEqual(treeHash(base), before);
});
