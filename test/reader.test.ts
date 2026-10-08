import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readFileSafe } from "../src/pipeline/reader.js";
import { Warnings } from "../src/pipeline/warnings.js";

function mkroot(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vuln-r-")));
}
const KEY = "AKIAABCDEFGHIJKLMNOP";

test("T-16 (F-04): file swapped for a symlink after listing", () => {
  const root = mkroot();
  const outside = mkroot();
  fs.mkdirSync(path.join(root, "src"));
  fs.writeFileSync(path.join(outside, "k.txt"), `k=${KEY}\n`);
  const f = path.join(root, "src", "a.js");
  fs.writeFileSync(f, "x\n");
  fs.rmSync(f);
  try {
    fs.symlinkSync(path.join(outside, "k.txt"), f, "file");
  } catch {
    return; // symlink creation not permitted on this host
  }
  const w = new Warnings();
  const r = readFileSafe(f, "src/a.js", { maxFileBytes: 1 << 20, warnings: w });
  assert.strictEqual(r, undefined);
  assert.strictEqual(w.count("W_FILE_CHANGED"), 1);
});

test("T-18 (F-07): deleted src/b.js", () => {
  const root = mkroot();
  fs.mkdirSync(path.join(root, "src"));
  for (const n of ["a.js", "c.js", "d.js"]) fs.writeFileSync(path.join(root, "src", n), "ok\n");
  const w = new Warnings();
  const names = ["a.js", "b.js", "c.js", "d.js"];
  const got = names.map((n) => readFileSafe(path.join(root, "src", n), `src/${n}`, { maxFileBytes: 1 << 20, warnings: w }));
  assert.strictEqual(w.count("W_FILE_VANISHED"), 1);
  assert.strictEqual(got.filter((g) => g !== undefined).length, 3);
});

test("T-19 (F-02): NUL at byte 10", () => {
  const root = mkroot();
  const f = path.join(root, "bin.dat");
  const b = Buffer.alloc(100, 0x41);
  b[10] = 0;
  fs.writeFileSync(f, b);
  const w = new Warnings();
  const r = readFileSafe(f, "bin.dat", { maxFileBytes: 1 << 20, warnings: w });
  assert.strictEqual(r, undefined);
  assert.strictEqual(w.count("W_BINARY_SKIPPED"), 1);
});

test("T-21 (F-01): file of maxFileBytes+1 bytes", () => {
  const root = mkroot();
  const f = path.join(root, "big.txt");
  fs.writeFileSync(f, "a".repeat(1024) + "\n".repeat(1) + KEY);
  const w = new Warnings();
  const r = readFileSafe(f, "big.txt", { maxFileBytes: 1024 + 1 + KEY.length - 1, warnings: w });
  assert.strictEqual(r, undefined);
  assert.strictEqual(w.count("W_FILE_TOO_LARGE"), 1);
});

test("file of exactly maxFileBytes bytes is read", () => {
  const root = mkroot();
  const f = path.join(root, "eq.txt");
  fs.writeFileSync(f, "a".repeat(2048));
  const w = new Warnings();
  const r = readFileSafe(f, "eq.txt", { maxFileBytes: 2048, warnings: w });
  assert.ok(r);
  assert.strictEqual(r.content.length, 2048);
  assert.strictEqual(w.count("W_FILE_TOO_LARGE"), 0);
});
