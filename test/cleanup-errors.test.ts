import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readFileSafe } from "../src/pipeline/reader.js";
import { Warnings } from "../src/pipeline/warnings.js";
import { writeReportFiles } from "../src/report/writer.js";
import { McpError } from "../src/errors.js";

function tmp(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vuln-c-")));
}
function errno(code: string): Error {
  return Object.assign(new Error(code), { code });
}
function read(closeCode: string) {
  const root = tmp();
  const f = path.join(root, "a.txt");
  fs.writeFileSync(f, "hi\n");
  const warnings = new Warnings();
  const r = readFileSafe(f, "a.txt", {
    maxFileBytes: 1000,
    warnings,
    closeSync: (fd) => {
      fs.closeSync(fd);
      throw errno(closeCode);
    },
  });
  return { r, warnings };
}

test("reader: EBADF on close is ignored", () => {
  const { r, warnings } = read("EBADF");
  assert.ok(r);
  assert.strictEqual(warnings.count("W_FILE_CHANGED"), 0);
});

test("reader: unexpected close error is recorded as a warning", () => {
  const { r, warnings } = read("EIO");
  assert.ok(r);
  assert.strictEqual(warnings.count("W_PERMISSION_DENIED"), 1);
  assert.strictEqual(warnings.count("W_FILE_CHANGED"), 0);
});

function write(unlinkCode: string, closeCode?: string) {
  const dir = tmp();
  try {
    writeReportFiles(dir, [{ name: "r.md", content: "x" }], {
      ops: {
        fsyncSync: () => {
          throw errno("EIO");
        },
        closeSync: closeCode
          ? () => {
              throw errno(closeCode);
            }
          : undefined,
        unlinkSync: () => {
          throw errno(unlinkCode);
        },
      },
    });
  } catch (e) {
    return e as McpError;
  }
  throw new Error("expected failure");
}

test("writer: ENOENT on unlink keeps original cause", () => {
  const e = write("ENOENT", "EBADF");
  assert.strictEqual(e.code, "E_WRITE_FAILED");
  assert.strictEqual((e.cause as NodeJS.ErrnoException).code, "EIO");
});

test("writer: unexpected cleanup failures are attached via cause, original code kept", () => {
  const e = write("EPERM", "EIO");
  assert.strictEqual(e.code, "E_WRITE_FAILED");
  assert.match(e.message, /EIO/);
  const agg = e.cause as AggregateError;
  assert.ok(agg instanceof AggregateError);
  assert.deepStrictEqual(agg.errors.map((x: NodeJS.ErrnoException) => x.code), ["EIO", "EIO", "EPERM"]);
});
