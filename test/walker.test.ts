import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { walk, type WalkOptions } from "../src/pipeline/walker.js";
import { Warnings } from "../src/pipeline/warnings.js";

function mk(files: string[]): string {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vuln-w-")));
  for (const f of files) {
    const p = path.join(root, ...f.split("/"));
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, "x");
  }
  return root;
}

function run(root: string, opts: WalkOptions = {}): { rels: string[]; w: Warnings } {
  const w = new Warnings();
  const rels = [...walk(root, opts, w)].map((e) => e.rel);
  return { rels, w };
}

const cp = (a: string, b: string): number => Buffer.compare(Buffer.from(a), Buffer.from(b));

test("traversal order equals code-point order of paths", () => {
  const root = mk(["b.txt", "a/z.txt", "a.txt", "a/b/c.txt", "Bx.txt", "a-x/y.txt", "é.txt", "z/1.txt"]);
  const { rels } = run(root);
  assert.strictEqual(rels.length, 8);
  assert.deepStrictEqual(rels, [...rels].sort(cp));
});

test("depth beyond MAX_DEPTH (64) stops descent and emits a warning", () => {
  const deep = Array.from({ length: 66 }, () => "d").join("/");
  const root = mk(["top.txt", `${deep}/deep.txt`]);
  const { rels, w } = run(root);
  assert.deepStrictEqual(rels, ["top.txt"]);
  assert.strictEqual(w.count("W_MAX_DEPTH"), 1);
});

test(".git, node_modules and .sast-audit directories are skipped", () => {
  const root = mk([".git/config", "node_modules/p/i.js", ".sast-audit/r.json", "src/a.js", "sub/node_modules/q.js"]);
  assert.deepStrictEqual(run(root).rels, ["src/a.js"]);
});

test("node_modules is walked when an includeGlobs entry matches it", () => {
  const root = mk(["node_modules/p/i.js", "src/a.js"]);
  const { rels } = run(root, { includeGlobs: ["node_modules/**"] });
  assert.deepStrictEqual(rels, ["node_modules/p/i.js", "src/a.js"]);
});

test(".gitignore matches are skipped when respectGitignore=true and walked when false", () => {
  const root = mk(["keep.js", "skip.log", "build/out.js", "sub/skip.log", "sub/ok.js"]);
  fs.writeFileSync(path.join(root, ".gitignore"), "*.log\nbuild/\n");
  assert.deepStrictEqual(run(root, { respectGitignore: true }).rels, [".gitignore", "keep.js", "sub/ok.js"]);
  assert.deepStrictEqual(run(root, { respectGitignore: false }).rels, [
    ".gitignore",
    "build/out.js",
    "keep.js",
    "skip.log",
    "sub/ok.js",
    "sub/skip.log",
  ]);
});

test("aborting the signal stops the walk before the next file", () => {
  const root = mk(["a.txt", "b.txt", "c.txt"]);
  const ac = new AbortController();
  const w = new Warnings();
  const it = walk(root, { signal: ac.signal }, w);
  const first = it.next();
  assert.strictEqual((first.value as { rel: string }).rel, "a.txt");
  ac.abort();
  const next = it.next();
  assert.strictEqual(next.done, true);
  assert.deepStrictEqual(next.value, { aborted: true, truncated: false });
});

test("walker: unreadable .gitignore warns W_PERMISSION_DENIED instead of being swallowed", () => {
  const root = mk(["a.txt"]);
  fs.mkdirSync(path.join(root, ".gitignore")); // directory: readFile -> EISDIR
  const { rels, w } = run(root);
  assert.deepStrictEqual(rels, ["a.txt"]);
  assert.strictEqual(w.count("W_PERMISSION_DENIED"), 1);
});
