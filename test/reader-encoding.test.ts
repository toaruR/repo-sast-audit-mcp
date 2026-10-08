import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readFileSafe } from "../src/pipeline/reader.js";
import { Warnings } from "../src/pipeline/warnings.js";
import { ABORT_CHECK_LINES, LINE_MAX } from "../src/constants.js";

function mkroot(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vuln-re-")));
}
const MAX = 1 << 22;

test("T-31 (F-02a): file with byte 0xE9", () => {
  const root = mkroot();
  const f = path.join(root, "l.txt");
  fs.writeFileSync(f, Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x0a]));
  const w = new Warnings();
  const r = readFileSafe(f, "l.txt", { maxFileBytes: MAX, warnings: w });
  assert.ok(r);
  assert.strictEqual(w.count("W_NON_UTF8"), 1);
  assert.strictEqual(r.content, "café\n");
  assert.strictEqual(r.nonUtf8, true);
});

test("T-32 (F-02b): line of LINE_MAX+1 (5001) chars", () => {
  const root = mkroot();
  const f = path.join(root, "m.js");
  fs.writeFileSync(f, `ok\n${"a".repeat(LINE_MAX + 1)}\nfine\n`);
  const w = new Warnings();
  const r = readFileSafe(f, "m.js", { maxFileBytes: MAX, warnings: w });
  assert.ok(r);
  assert.strictEqual(w.count("W_MINIFIED_SKIPPED"), 1);
  assert.deepStrictEqual(r.minifiedLines, [2]);
});

test("T-23 (F-07a) part: unreadable inner file", () => {
  const root = mkroot();
  const f = path.join(root, "locked.txt");
  fs.writeFileSync(f, "secret\n");
  const w = new Warnings();
  const r = readFileSafe(f, "locked.txt", {
    maxFileBytes: MAX,
    warnings: w,
    openSync: () => {
      throw Object.assign(new Error("denied"), { code: "EACCES" });
    },
  });
  assert.strictEqual(r, undefined);
  assert.strictEqual(w.count("W_PERMISSION_DENIED"), 1);
});

test("T-23 (F-07a) part: siblings of the unreadable file are still read", () => {
  const root = mkroot();
  for (const n of ["a.txt", "locked.txt", "z.txt"]) fs.writeFileSync(path.join(root, n), "hi\n");
  const w = new Warnings();
  const results = ["a.txt", "locked.txt", "z.txt"].map((n) =>
    readFileSafe(path.join(root, n), n, {
      maxFileBytes: MAX,
      warnings: w,
      openSync: (p, flags) => {
        if (p.endsWith("locked.txt")) throw Object.assign(new Error("denied"), { code: "EACCES" });
        return fs.openSync(p, flags);
      },
    }),
  );
  assert.deepStrictEqual(results.map((r) => r !== undefined), [true, false, true]);
  assert.strictEqual(w.count("W_PERMISSION_DENIED"), 1);
});

test("abort inside a file stops after at most ABORT_CHECK_LINES (1000) lines", () => {
  const root = mkroot();
  const f = path.join(root, "long.txt");
  fs.writeFileSync(f, "x\n".repeat(5000));
  let checks = 0;
  const signal = {
    get aborted(): boolean {
      checks++;
      return checks > 2; // 1st: before open, 2nd: at line 0, 3rd: at line 1000
    },
  } as unknown as AbortSignal;
  const w = new Warnings();
  const r = readFileSafe(f, "long.txt", { maxFileBytes: MAX, warnings: w, signal });
  assert.ok(r);
  assert.strictEqual(r.aborted, true);
  assert.ok(r.lineCount <= ABORT_CHECK_LINES);
});

test("signal already aborted before open => file is not read", () => {
  const root = mkroot();
  const f = path.join(root, "a.txt");
  fs.writeFileSync(f, "x\n");
  const ac = new AbortController();
  ac.abort();
  let opened = false;
  const w = new Warnings();
  const r = readFileSafe(f, "a.txt", {
    maxFileBytes: MAX,
    warnings: w,
    signal: ac.signal,
    openSync: (p, flags) => {
      opened = true;
      return fs.openSync(p, flags);
    },
  });
  assert.strictEqual(r, undefined);
  assert.strictEqual(opened, false);
});
