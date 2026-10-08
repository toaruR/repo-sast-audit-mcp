import { createHash } from "node:crypto";
import type { Rule } from "./rules.js";

function canon(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canon);
  if (v !== null && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) o[k] = canon((v as Record<string, unknown>)[k]);
    return o;
  }
  return v;
}

/** SHA-256 (lowercase hex) of the rules sorted by id plus scanner versions sorted by scanner id. */
export function rulesetHash(rules: readonly Rule[], scannerVersions: Readonly<Record<string, string>>): string {
  const sortedRules = [...rules]
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map((r) => canon({
      id: r.id, title: r.title, languages: r.languages, pattern: r.pattern, negativePattern: r.negativePattern ?? null,
      severity: r.severity, confidence: r.confidence, cwe: r.cwe, tests: r.tests,
    }));
  const versions = Object.keys(scannerVersions).sort().map((k) => [k, scannerVersions[k]]);
  return createHash("sha256").update(JSON.stringify({ rules: sortedRules, scanners: versions }), "utf8").digest("hex");
}
