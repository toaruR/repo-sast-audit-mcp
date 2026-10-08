import { test } from "node:test";
import assert from "node:assert";
import * as C from "../src/constants.js";

const rows: [string, Record<string, number>][] = [
  ["runtime: targets", { PERF_TARGET_S: 20, PEAK_RSS_MIB: 400, DEP_MAX: 9 }],
  ["runtime: job slots", { MAX_RUNNING: 2, MAX_QUEUED: 8, JOB_KEEP: 20 }],
  ["runtime: timing", { PER_FILE_BUDGET_MS: 2000, CANCEL_DRAIN_MS: 3000 }],
  ["runtime: staleness and cache", { STALE_DAYS: 30, ABORT_CHECK_LINES: 1000, SHARD_LRU: 256 }],
  ["runtime: secret thresholds", { SECRET_MIN_LEN: 20, HEX_MIN_LEN: 32, ENT_ALNUM_MILLI: 4000, ENT_HEX_MILLI: 3200 }],
  ["runtime: redaction", { REDACT_PREFIX: 4, LEAK_SUBSTR: 5 }],
];
for (const [title, expected] of rows) {
  test(title, () => {
    for (const [k, v] of Object.entries(expected)) {
      assert.strictEqual((C as Record<string, unknown>)[k], v, k);
    }
  });
}
