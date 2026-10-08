import { test } from "node:test";
import assert from "node:assert";
import { normalize, redact, redactPem } from "../src/security/redact.js";

test("redact of a 20-char value returns first 4 chars + ****[REDACTED len=20]", () => {
  assert.strictEqual(redact("AKIAABCDEFGHIJKLMNOP"), "AKIA****[REDACTED len=20]");
});
test("redact of a 7-char value returns ****[REDACTED len=7] (no prefix)", () => {
  assert.strictEqual(redact("abcdefg"), "****[REDACTED len=7]");
});
test("redact of an 8-char value keeps a 4-char prefix", () => {
  assert.strictEqual(redact("abcdefgh"), "abcd****[REDACTED len=8]");
});
test("PEM body lines never appear in evidence; only the redacted BEGIN line marker remains", () => {
  const body = ["MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA=="];
  const pem = ["-----BEGIN RSA PRIVATE KEY-----", ...body, "-----END RSA PRIVATE KEY-----"].join("\n");
  const ev = redactPem(pem);
  for (const b of body) assert.ok(!ev.includes(b.slice(0, 5)));
  assert.ok(ev.startsWith("----"));
  assert.ok(ev.includes("[REDACTED len=31]"));
});
test("T-28 (F-13): normalize turns evidence holding AKIA+16 chars into \"[REDACTED line]\"", () => {
  const raw = "AKIAABCDEFGHIJKLMNOP";
  assert.strictEqual(normalize(`key = ${raw}`, raw), "[REDACTED line]");
  assert.strictEqual(normalize(redact(raw), raw), redact(raw));
});
test("T-28 (F-13): innocent text sharing a LEAK_SUBSTR (5) char substring with a secret is also blanked (documented false positive, section 11)", () => {
  assert.strictEqual(normalize("see ABCDE docs", "AKIAABCDEFGHIJKLMNOP"), "[REDACTED line]");
});
