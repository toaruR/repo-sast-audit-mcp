import { test } from "node:test";
import assert from "node:assert";
import * as C from "../src/constants.js";

const rows: [string, Record<string, number>][] = [
  ["sizes: globs and prefix", { GLOB_N: 50, GLOB_LEN: 256, PATHPREFIX_MAX: 1024 }],
  ["sizes: paging", { GET_FINDINGS_MAX: 200, CURSOR_MAX: 256 }],
  ["sizes: path and rule id", { PATH_MAX: 4096, RULEID_MAX: 64 }],
  ["sizes: walker and lockfile", { MAX_DEPTH: 64, LINE_MAX: 5000, LOCKFILE_MAX_BYTES: 16777216 }],
  ["sizes: probe and secret window", { BINARY_PROBE_BYTES: 8192, SECRET_WINDOW_BYTES: 4096 }],
  ["sizes: evidence", { EVIDENCE_MAX: 200 }],
];
for (const [title, expected] of rows) {
  test(title, () => {
    for (const [k, v] of Object.entries(expected)) {
      assert.strictEqual((C as Record<string, unknown>)[k], v, k);
    }
  });
}
