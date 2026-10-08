import { LEAK_SUBSTR, REDACT_PREFIX } from "../constants.js";

export const REDACTED_LINE = "[REDACTED line]";

export function redact(v: string): string {
  const chars = [...v];
  const n = chars.length;
  const prefix = n < 8 ? "" : chars.slice(0, REDACT_PREFIX).join("");
  return `${prefix}****[REDACTED len=${n}]`;
}

/** Evidence for a PEM block: only the redacted BEGIN marker line; body lines are dropped. */
export function redactPem(block: string): string {
  const lines = block.split(/\r?\n/);
  const begin = lines.find((l) => l.includes("-----BEGIN")) ?? lines[0] ?? "";
  return redact(begin.trim());
}

/** True when any LEAK_SUBSTR-char substring of raw (not the allowed prefix-only) occurs in text. */
export function leaksSubstring(text: string, raw: string): boolean {
  const chars = [...raw];
  for (let i = 0; i + LEAK_SUBSTR <= chars.length; i++) {
    if (text.includes(chars.slice(i, i + LEAK_SUBSTR).join(""))) return true;
  }
  return false;
}

/**
 * Replace evidence by "[REDACTED line]" if a LEAK_SUBSTR-char substring of the raw value remains.
 * Documented false positive (design section 11): innocent text sharing such a substring is blanked too.
 */
export function normalize(evidence: string, raw: string): string {
  return leaksSubstring(evidence, raw) ? REDACTED_LINE : evidence;
}
