import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { validateOutputDir } from "../src/security/paths.js";

const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vuln-od-")));
const repo = path.join(base, "repo");
fs.mkdirSync(path.join(repo, "src"), { recursive: true });
fs.mkdirSync(path.join(repo, ".git"));
fs.writeFileSync(path.join(repo, "src", "a.js"), "x");
const outRoot = path.join(base, "out");
const opts = { allowedRoots: [base], outputRoot: outRoot, scanId: "S-0123456789ab-1" };

const code = (outputDir: string, allow = false): string | undefined => {
  try {
    validateOutputDir(repo, { ...opts, outputDir, allowWriteInsideTarget: allow });
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

const before = treeHash(repo);

test("T-10b (F-11): outputDir inside the target => E_OUTPUT_DIR_UNSAFE", () => {
  assert.strictEqual(code(path.join(repo, "reports")), "E_OUTPUT_DIR_UNSAFE");
});
test("T-10b (F-11): outputDir that is an ancestor of the target => E_OUTPUT_DIR_UNSAFE", () => {
  assert.strictEqual(code(base), "E_OUTPUT_DIR_UNSAFE");
  assert.strictEqual(code(base, true), "E_OUTPUT_DIR_UNSAFE");
});
test("T-10b (F-11): outputDir that is a symlink into the target => E_OUTPUT_DIR_UNSAFE", () => {
  const link = path.join(base, "link");
  fs.symlinkSync(path.join(repo, "src"), link, "junction");
  assert.strictEqual(code(link), "E_OUTPUT_DIR_UNSAFE");
  assert.strictEqual(code(path.join(link, "new")), "E_OUTPUT_DIR_UNSAFE");
});
test("outputDir under <repo>/.git/ => E_OUTPUT_DIR_UNSAFE even with allowWriteInsideTarget=true", () => {
  assert.strictEqual(code(path.join(repo, ".git", "x"), true), "E_OUTPUT_DIR_UNSAFE");
  assert.strictEqual(code(path.join(repo, ".git"), true), "E_OUTPUT_DIR_UNSAFE");
});
test("target tree hash is unchanged after all unsafe attempts", () => {
  assert.strictEqual(treeHash(repo), before);
  assert.strictEqual(fs.existsSync(path.join(repo, "reports")), false);
});
