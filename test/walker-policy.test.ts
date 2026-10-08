import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { walk, type WalkOptions, type WalkResult } from "../src/pipeline/walker.js";
import { Warnings } from "../src/pipeline/warnings.js";

function mk(files: string[]): string {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vuln-wp-")));
  for (const f of files) {
    const p = path.join(root, ...f.split("/"));
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, "x");
  }
  return root;
}

function run(root: string, opts: WalkOptions = {}): { rels: string[]; w: Warnings; res: WalkResult } {
  const w = new Warnings();
  const it = walk(root, opts, w);
  const rels: string[] = [];
  for (;;) {
    const n = it.next();
    if (n.done) return { rels, w, res: n.value };
    rels.push(n.value.rel);
  }
}

const code = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return (e as { code?: string }).code;
  }
  return undefined;
};

test("T-09 (F-03): symlink loop a->. terminates and emits W_SYMLINK_SKIPPED (no hang)", () => {
  const root = mk(["real.txt"]);
  fs.symlinkSync(root, path.join(root, "a"), "junction");
  const { rels, w } = run(root, { symlinkPolicy: "follow-within-root" });
  assert.deepStrictEqual(rels, ["real.txt"]);
  assert.ok(w.count("W_SYMLINK_SKIPPED") >= 1);
});

test("T-09 (F-03): follow-within-root with a link to a dir holding an AKIA key outside root emits W_SYMLINK_ESCAPE and no outside content is read", () => {
  const outside = mk(["secret.txt"]);
  fs.writeFileSync(path.join(outside, "secret.txt"), "AKIAABCDEFGHIJKLMNOP");
  const root = mk(["in.txt"]);
  fs.symlinkSync(outside, path.join(root, "esc"), "junction");
  const reads: string[] = [];
  const orig = fs.readFileSync;
  (fs as unknown as { readFileSync: unknown }).readFileSync = (p: unknown, ...a: unknown[]) => {
    reads.push(String(p));
    return (orig as (...x: unknown[]) => unknown)(p, ...a);
  };
  let r: ReturnType<typeof run>;
  try {
    r = run(root, { symlinkPolicy: "follow-within-root" });
  } finally {
    (fs as unknown as { readFileSync: unknown }).readFileSync = orig;
  }
  assert.deepStrictEqual(r.rels, ["in.txt"]);
  assert.strictEqual(r.w.count("W_SYMLINK_ESCAPE"), 1);
  assert.ok(!reads.some((p) => p.includes(path.basename(outside))));
});

test("follow-within-root follows a link to a directory inside the root", () => {
  const root = mk(["d/f.txt"]);
  fs.symlinkSync(path.join(root, "d"), path.join(root, "link"), "junction");
  const { rels } = run(root, { symlinkPolicy: "follow-within-root", respectGitignore: false });
  assert.deepStrictEqual(rels, ["d/f.txt"]);
});

test("excludeGlobs entries exclude matching files", () => {
  const root = mk(["a.js", "b.min.js", "docs/x.md", "docs/y.js"]);
  const { rels } = run(root, { excludeGlobs: ["**/*.min.js", "docs/**"] });
  assert.deepStrictEqual(rels, ["a.js"]);
});

test("51 globs (more than GLOB_N) => E_INVALID_INPUT", () => {
  const root = mk(["a.js"]);
  const globs = Array.from({ length: 51 }, (_, i) => `g${i}`);
  assert.strictEqual(code(() => run(root, { excludeGlobs: globs })), "E_INVALID_INPUT");
  assert.strictEqual(code(() => run(root, { includeGlobs: globs })), "E_INVALID_INPUT");
});

test("a glob of 257 chars (more than GLOB_LEN) => E_INVALID_INPUT", () => {
  const root = mk(["a.js"]);
  assert.strictEqual(code(() => run(root, { excludeGlobs: ["a".repeat(257)] })), "E_INVALID_INPUT");
  assert.strictEqual(code(() => run(root, { excludeGlobs: ["a".repeat(256)] })), undefined);
});

test("maxFiles=2 on a 5-file tree => truncated true and a W_* warning", () => {
  const root = mk(["a", "b", "c", "d", "e"]);
  const { rels, w, res } = run(root, { maxFiles: 2 });
  assert.deepStrictEqual(rels, ["a", "b"]);
  assert.strictEqual(res.truncated, true);
  assert.strictEqual(w.count("W_MAX_FILES"), 1);
  assert.strictEqual(run(root, { maxFiles: 5 }).res.truncated, false);
});
