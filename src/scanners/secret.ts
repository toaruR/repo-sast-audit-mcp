import { RE2 } from "re2-wasm";
import { ENT_ALNUM_MILLI, ENT_HEX_MILLI, HEX_MIN_LEN, SECRET_MIN_LEN, SECRET_WINDOW_BYTES } from "../constants.js";
import type { Confidence, Severity } from "../scoring.js";

export interface SecretMatch {
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  line: number;
  column: number;
  /** Raw matched secret value (must never leave the process unredacted). */
  raw: string;
}

interface Rule {
  id: string;
  pattern: string;
  flags: string;
  severity: Severity;
  confidence: Confidence;
}

// RE2 only: no lookaround, no backreferences.
export const SECRET_PATTERNS: readonly Rule[] = [
  { id: "SEC-AWS-ACCESS-KEY-ID", pattern: String.raw`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`, flags: "gu", severity: "critical", confidence: "high" },
  { id: "SEC-PRIVATE-KEY", pattern: "-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----", flags: "gu", severity: "critical", confidence: "high" },
  { id: "SEC-GITHUB-TOKEN", pattern: String.raw`\bgh[pousr]_[A-Za-z0-9]{36}\b`, flags: "gu", severity: "high", confidence: "high" },
];

const GENERIC_ID = "SEC-GENERIC-HIGH-ENTROPY";
const GENERIC_PATTERN = String.raw`(?:secret|token|password|api_key)\w*["']?\s*[:=]\s*["']([^"'\s]+)["']`;
export const GENERIC_SOURCE = GENERIC_PATTERN;

const compiled = SECRET_PATTERNS.map((r) => ({ rule: r, re: new RE2(r.pattern, r.flags) }));
const genericRe = new RE2(GENERIC_PATTERN, "giu");
const hexRe = new RE2("^[0-9a-fA-F]+$", "u");

export function shannonMilli(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const n = [...s].length;
  let h = 0;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return Math.round(h * 1000);
}

export function isPlaceholder(v: string): boolean {
  const l = v.toLowerCase();
  return l.includes("example") || l.includes("your_") || l.includes("${");
}

export function isExampleEnvFile(path: string): boolean {
  const base = (path.split(/[\\/]/).pop() ?? "").toLowerCase();
  return base === ".env.example" || base.endsWith(".env.example");
}

function genericQualifies(v: string): boolean {
  if (isPlaceholder(v)) return false;
  if (v.length >= HEX_MIN_LEN && hexRe.test(v)) return shannonMilli(v) >= ENT_HEX_MILLI;
  if (v.length >= SECRET_MIN_LEN) return shannonMilli(v) >= ENT_ALNUM_MILLI;
  return false;
}

const OVERLAP = 256;

function* windows(line: string): Generator<[number, string]> {
  if (line.length <= SECRET_WINDOW_BYTES) {
    yield [0, line];
    return;
  }
  const step = SECRET_WINDOW_BYTES - OVERLAP;
  for (let off = 0; off < line.length; off += step) {
    yield [off, line.slice(off, off + SECRET_WINDOW_BYTES)];
    if (off + SECRET_WINDOW_BYTES >= line.length) break;
  }
}

function scanWindow(text: string, base: number, lineNo: number, out: Map<string, SecretMatch>): void {
  for (const { rule, re } of compiled) {
    re.lastIndex = 0;
    let m: ReturnType<RE2["exec"]>;
    while ((m = re.exec(text)) !== null) {
      const raw = m[0] ?? "";
      if (raw.length === 0) {
        re.lastIndex++;
        continue;
      }
      if (rule.id !== "SEC-PRIVATE-KEY" && isPlaceholder(raw)) continue;
      const column = base + m.index + 1;
      out.set(`${rule.id}:${column}`, {
        ruleId: rule.id, severity: rule.severity, confidence: rule.confidence, line: lineNo, column, raw,
      });
    }
  }
  genericRe.lastIndex = 0;
  let g: ReturnType<RE2["exec"]>;
  while ((g = genericRe.exec(text)) !== null) {
    const v = g[1] ?? "";
    const whole = g[0] ?? "";
    if (whole.length === 0) {
      genericRe.lastIndex++;
      continue;
    }
    if (!genericQualifies(v)) continue;
    const column = base + g.index + whole.lastIndexOf(v) + 1;
    out.set(`${GENERIC_ID}:${column}`, {
      ruleId: GENERIC_ID, severity: "high", confidence: "medium", line: lineNo, column, raw: v,
    });
  }
}

export function scanSecrets(path: string, content: string): SecretMatch[] {
  if (isExampleEnvFile(path)) return [];
  const out = new Map<string, SecretMatch>();
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? "").replace(/\r$/, "");
    for (const [off, w] of windows(line)) scanWindow(w, off, i + 1, out);
  }
  return [...out.values()].sort((a, b) => a.line - b.line || a.column - b.column || (a.ruleId < b.ruleId ? -1 : 1));
}
