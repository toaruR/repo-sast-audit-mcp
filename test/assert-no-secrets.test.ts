import { test } from "node:test";
import assert from "node:assert";
import { assertNoSecrets } from "../src/security/assertNoSecrets.js";
import { redact } from "../src/security/redact.js";

const RAW = "wJalrXUtnFEMIK7MDENGbPxRfiCYzzzz";
const isInternal = (e: unknown): boolean => (e as { code?: string }).code === "E_INTERNAL";

test("output holding a 5-char substring of a detected secret past REDACT_PREFIX makes assertNoSecrets throw E_INTERNAL", () => {
  assert.throws(() => assertNoSecrets(`leak: ${RAW.slice(4, 9)}`, [RAW]), isInternal);
});
test("output holding only the 4-char REDACT_PREFIX of the secret does not throw", () => {
  assert.doesNotThrow(() => assertNoSecrets(`evidence: ${redact(RAW)}`, [RAW]));
  assert.doesNotThrow(() => assertNoSecrets(`prefix ${RAW.slice(0, 4)} only`, [RAW]));
});
test("output holding AKIA+16 chars throws E_INTERNAL even when the secret was not registered", () => {
  assert.throws(() => assertNoSecrets("x AKIAABCDEFGHIJKLMNOP y"), isInternal);
});
test("clean output (no secret substring) does not throw", () => {
  assert.doesNotThrow(() => assertNoSecrets("Scan finished: 3 findings", [RAW]));
});
