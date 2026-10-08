import crypto from "node:crypto";
import { McpError } from "../errors.js";
import type { Confidence, Severity } from "../scoring.js";

export type ScannerKind = "dependency" | "secret" | "static" | "config";

export interface Finding {
  id: string;
  ruleId: string;
  scanner: ScannerKind;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string[];
  location: { path: string; line: number; column: number };
  evidence: string;
  message: string;
  remediation: string;
  fingerprint: string;
  occurrence: number;
  advisoryId?: string;
  relatedRuleIds?: string[];
  cvss?: { score: number; version: string };
  package?: { ecosystem: string; name: string; version: string; fixedIn?: string };
}

/** A finding before identity (id, fingerprint, occurrence) is assigned. */
export type RawFinding = Omit<Finding, "id" | "fingerprint" | "occurrence">;

const LF = "\n";
const sha256 = (s: string): string => crypto.createHash("sha256").update(s, "utf8").digest("hex");
const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Canonical evidence: line endings normalized to LF. */
export function canonEvidence(evidence: string): string {
  return evidence.replace(/\r\n?/g, "\n");
}

/** location.path is relative with forward slashes; absolute paths are rejected. */
export function normalizeLocationPath(p: string): string {
  if (/^(?:\/|\\|[A-Za-z]:)/.test(p)) throw new McpError("E_INTERNAL", "location.path must be relative");
  return p.replace(/\\/g, "/");
}

export function fpBase(f: { ruleId: string; path: string; evidence: string; advisoryId?: string | undefined }): string {
  return [f.ruleId, f.path, canonEvidence(f.evidence), f.advisoryId ?? ""].join(LF);
}

/** Append -1, -2, ... to repeated ids (first occurrence keeps the plain id). Input order is preserved. */
export function resolveIdCollisions(ids: readonly string[]): string[] {
  const seen = new Map<string, number>();
  return ids.map((id) => {
    const n = seen.get(id) ?? 0;
    seen.set(id, n + 1);
    return n === 0 ? id : `${id}-${n}`;
  });
}

/** Assign occurrence, fingerprint and id to raw findings. Result is independent of input order. */
export function assignIdentity(raw: readonly RawFinding[]): Finding[] {
  const items = raw.map((f) => {
    const p = normalizeLocationPath(f.location.path);
    return { f: { ...f, location: { ...f.location, path: p } }, base: fpBase({ ruleId: f.ruleId, path: p, evidence: f.evidence, advisoryId: f.advisoryId }) };
  });
  items.sort(
    (a, b) =>
      cmp(a.base, b.base) ||
      cmp(a.f.location.path, b.f.location.path) ||
      a.f.location.line - b.f.location.line ||
      a.f.location.column - b.f.location.column ||
      cmp(a.f.scanner, b.f.scanner) ||
      cmp(a.f.title, b.f.title),
  );
  const rank = new Map<string, number>();
  const out: Finding[] = items.map(({ f, base }) => {
    const occurrence = (rank.get(base) ?? 0) + 1;
    rank.set(base, occurrence);
    const fingerprint = sha256([base, String(occurrence)].join(LF)).slice(0, 32);
    const id =
      "F-" +
      sha256([f.ruleId, f.location.path, String(f.location.line), String(f.location.column), fingerprint].join(LF)).slice(0, 16);
    return { ...f, id, fingerprint, occurrence };
  });
  const ids = resolveIdCollisions(out.map((f) => f.id));
  return out.map((f, i) => ({ ...f, id: ids[i] as string }));
}
