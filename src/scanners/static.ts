import { LINE_MAX, PER_FILE_BUDGET_MS } from "../constants.js";
import type { Warnings } from "../pipeline/warnings.js";
import type { Confidence, Severity } from "../scoring.js";
import type { CompiledRule, RuleLanguage } from "./rules.js";

export interface StaticMatch {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string;
  line: number;
  column: number;
}

export interface StaticOptions {
  /** Monotonic millisecond clock; injectable for tests. */
  now?: () => number;
  /** Set false when the reader already recorded W_MINIFIED_SKIPPED for this file. */
  warnMinified?: boolean;
}

export function languagesOf(rel: string): Set<RuleLanguage> {
  const out = new Set<RuleLanguage>(["any"]);
  const base = (rel.split("/").pop() ?? "").toLowerCase();
  if (/\.(?:[cm]?js|jsx|tsx?)$/.test(base)) out.add("javascript");
  else if (/\.pyw?$/.test(base)) out.add("python");
  else if (/\.ya?ml$/.test(base)) {
    out.add("yaml");
    if (/^\.github\/workflows\//.test(rel)) out.add("github-actions");
  } else if (base === "dockerfile" || base.startsWith("dockerfile.") || base.endsWith(".dockerfile")) {
    out.add("dockerfile");
  }
  return out;
}

/** Runs JSON (RE2) rules line by line. Lines longer than LINE_MAX are skipped. */
export function scanStatic(
  rel: string,
  content: string,
  rules: readonly CompiledRule[],
  warnings: Warnings,
  opts: StaticOptions = {},
): StaticMatch[] {
  const langs = languagesOf(rel);
  const applicable = rules.filter((r) => r.languages.some((l) => langs.has(l)));
  if (applicable.length === 0) return [];
  const now = opts.now ?? ((): number => performance.now());
  const start = now();
  const out: StaticMatch[] = [];
  let minified = false;
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (now() - start > PER_FILE_BUDGET_MS) {
      warnings.add("W_RULE_TIMEBUDGET", rel);
      break;
    }
    const line = (lines[i] ?? "").replace(/\r$/, "");
    if (line.length > LINE_MAX) {
      minified = true;
      continue;
    }
    for (const r of applicable) {
      if (r.neg !== undefined) {
        r.neg.lastIndex = 0;
        const negHit = r.neg.exec(line) !== null;
        r.neg.lastIndex = 0;
        if (negHit) continue;
      }
      r.re.lastIndex = 0;
      let m: ReturnType<typeof r.re.exec>;
      while ((m = r.re.exec(line)) !== null) {
        if ((m[0] ?? "").length === 0) {
          r.re.lastIndex++;
          continue;
        }
        out.push({
          ruleId: r.id, title: r.title, severity: r.severity, confidence: r.confidence, cwe: r.cwe,
          line: i + 1, column: m.index + 1,
        });
      }
      r.re.lastIndex = 0;
    }
  }
  if (minified && opts.warnMinified !== false) warnings.add("W_MINIFIED_SKIPPED", rel);
  return out;
}
