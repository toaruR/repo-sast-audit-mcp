import type { Finding } from "./identity.js";

const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 } as const;
const CONF = { high: 2, medium: 1, low: 0 } as const;
const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Total order (design 5.3): severity desc, confidence desc, path asc (code point), line, column, ruleId, id. */
export function compareFindings(a: Finding, b: Finding): number {
  return (
    SEV[b.severity] - SEV[a.severity] ||
    CONF[b.confidence] - CONF[a.confidence] ||
    cmp(a.location.path, b.location.path) ||
    a.location.line - b.location.line ||
    a.location.column - b.location.column ||
    cmp(a.ruleId, b.ruleId) ||
    cmp(a.id, b.id)
  );
}

export function sortFindings<T extends Finding>(findings: readonly T[]): T[] {
  return [...findings].sort(compareFindings);
}
