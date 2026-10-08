import { test } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { writeReportFiles } from "../src/report/writer.js";

const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vuln-wr-")));
let n = 0;
const fresh = (): string => path.join(base, `d${n++}`);
const tmps = (d: string): string[] => fs.readdirSync(d).filter((f) => f.endsWith(".tmp"));
const sha = (b: Buffer | string): string => crypto.createHash("sha256").update(b).digest("hex");
const three = [
  { name: "report.md", content: "# md\n" },
  { name: "report.json", content: "{}\n" },
  { name: "report.sarif.json", content: "{\"v\":1}\n" },
];

function failingRename(second: string) {
  return (a: string, b: string): void => {
    if (path.basename(b) === second) throw Object.assign(new Error("boom"), { code: "EIO" });
    fs.renameSync(a, b);
  };
}

test("writes all files and reports bytes and sha256", () => {
  const d = fresh();
  const r = writeReportFiles(d, three);
  assert.strictEqual(r.length, 3);
  assert.strictEqual(fs.readFileSync(path.join(d, "report.md"), "utf8"), "# md\n");
  assert.strictEqual(r[1]?.sha256, sha("{}\n"));
  assert.strictEqual(r[1]?.bytes, 3);
  assert.strictEqual(tmps(d).length, 0);
});

test("T-26: stub rename failing EIO on the 2nd of 3 files => E_WRITE_FAILED with retryable true", () => {
  const d = fresh();
  assert.throws(
    () => writeReportFiles(d, three, { ops: { renameSync: failingRename("report.json") } }),
    (e: unknown) => (e as { code?: string }).code === "E_WRITE_FAILED",
  );
});

test("T-26: after the failure the *.tmp count is 0 and the error message names the failed file", () => {
  const d = fresh();
  try {
    writeReportFiles(d, three, { ops: { renameSync: failingRename("report.json") } });
    assert.fail("expected throw");
  } catch (e) {
    assert.match((e as Error).message, /report\.json/);
  }
  assert.strictEqual(tmps(d).length, 0);
});

test("F-11a: the first (already renamed) file stays in place (partial set)", () => {
  const d = fresh();
  assert.throws(() => writeReportFiles(d, three, { ops: { renameSync: failingRename("report.json") } }));
  assert.ok(fs.existsSync(path.join(d, "report.md")));
  assert.ok(!fs.existsSync(path.join(d, "report.json")));
  assert.ok(!fs.existsSync(path.join(d, "report.sarif.json")));
});

test("an existing target file keeps its old content when its rename fails", () => {
  const d = fresh();
  fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(d, "report.json"), "OLD");
  assert.throws(() => writeReportFiles(d, three, { ops: { renameSync: failingRename("report.json") } }));
  assert.strictEqual(fs.readFileSync(path.join(d, "report.json"), "utf8"), "OLD");
  assert.strictEqual(tmps(d).length, 0);
});

test("tmp files are opened with flag wx: when the tmp name already exists the open fails with EEXIST and the pre-existing file's SHA-256 is unchanged", () => {
  const d = fresh();
  fs.mkdirSync(d, { recursive: true });
  const pre = path.join(d, "fixed.tmp");
  fs.writeFileSync(pre, "PRE-EXISTING");
  const before = sha(fs.readFileSync(pre));
  const flags: string[] = [];
  let opened: unknown;
  assert.throws(
    () =>
      writeReportFiles(d, three, {
        tmpName: () => "fixed.tmp",
        ops: {
          openSync: (f, fl) => {
            flags.push(fl);
            try {
              return fs.openSync(f, fl);
            } catch (e) {
              opened = (e as NodeJS.ErrnoException).code;
              throw e;
            }
          },
        },
      }),
    (e: unknown) => (e as { code?: string }).code === "E_WRITE_FAILED",
  );
  assert.deepStrictEqual(flags, ["wx"]);
  assert.strictEqual(opened, "EEXIST");
  assert.strictEqual(sha(fs.readFileSync(pre)), before);
});
