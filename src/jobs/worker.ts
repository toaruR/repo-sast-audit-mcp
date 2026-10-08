import { isMainThread, parentPort, threadId, workerData } from "node:worker_threads";
import { EVIDENCE_MAX, LIMITS } from "../constants.js";
import { loadAdvisoryDb, type AdvisoryDb } from "../advisory/db.js";
import { McpError } from "../errors.js";
import { dedupeFindings } from "../findings/dedupe.js";
import { assignIdentity, type Finding, type RawFinding } from "../findings/identity.js";
import { truncateTopK } from "../findings/truncate.js";
import { createOsvClient } from "../net/osvClient.js";
import { readFileSafe } from "../pipeline/reader.js";
import { walk } from "../pipeline/walker.js";
import { Warnings, type Warning } from "../pipeline/warnings.js";
import { checkLockfilesMissing, lockfileKind } from "../scanners/lockfiles.js";
import { scanConfig } from "../scanners/config.js";
import { scanDependencies, type DependencyFile } from "../scanners/dependency.js";
import { loadRules } from "../scanners/rules.js";
import { scanSecrets } from "../scanners/secret.js";
import { scanStatic } from "../scanners/static.js";
import { normalize, redact, redactPem } from "../security/redact.js";
import { sanitize } from "../security/sanitize.js";

export interface RunSpec {
  repoPath: string;
  scanners: readonly string[];
  options: Record<string, unknown>;
  /** Advisory DB directory (already resolved by the submit path), if any. */
  dbPath?: string | undefined;
  /** Optional shared flag: a non-zero Int32 at index 0 requests an abort. */
  abortFlag?: SharedArrayBuffer | undefined;
}

export interface WorkerProgress {
  type: "progress";
  filesScanned: number;
  bytesScanned: number;
  findingsSoFar: number;
}

export interface WorkerDone {
  type: "done";
  findings: Finding[];
  warnings: Warning[];
  filesScanned: number;
  bytesScanned: number;
  truncated: boolean;
  /** True when a cap (maxFiles, maxTotalBytes, maxFindings) was hit. */
  capHit: boolean;
  aborted: boolean;
  /** worker_threads.threadId of the scanning worker (diagnostics only; never exposed in tool output). */
  threadId?: number;
}

export type WorkerMessage = WorkerProgress | WorkerDone;

const SECRET_TITLES: Record<string, string> = {
  "SEC-AWS-ACCESS-KEY-ID": "AWS access key id in source",
  "SEC-PRIVATE-KEY": "Private key in source",
  "SEC-GITHUB-TOKEN": "GitHub token in source",
  "SEC-GENERIC-HIGH-ENTROPY": "High-entropy secret in source",
};

function numOpt(opts: Record<string, unknown>, key: string, fallback: number): number {
  const limits = (opts["limits"] ?? {}) as Record<string, unknown>;
  const v = limits[key];
  return typeof v === "number" ? v : fallback;
}

/** Evidence for text taken from the repo: sanitized, cut, and blanked if it leaks a known secret. */
function safeEvidence(text: string, secrets: readonly string[]): string {
  let ev = sanitize(text.trim(), EVIDENCE_MAX);
  for (const raw of secrets) ev = normalize(ev, raw);
  return ev;
}

/** Runs the whole pipeline synchronously except the dependency step. */
export async function runScan(spec: RunSpec, post: (m: WorkerMessage) => void): Promise<WorkerDone> {
  const opts = spec.options;
  const want = new Set(spec.scanners);
  const warnings = new Warnings();
  const abortController = new AbortController();
  const flag = spec.abortFlag ? new Int32Array(spec.abortFlag) : undefined;
  const checkAbort = (): boolean => {
    if (flag && Atomics.load(flag, 0) !== 0) abortController.abort();
    return abortController.signal.aborted;
  };
  const maxFiles = numOpt(opts, "maxFiles", LIMITS.maxFiles.default);
  const maxFileBytes = numOpt(opts, "maxFileBytes", LIMITS.maxFileBytes.default);
  const maxTotalBytes = numOpt(opts, "maxTotalBytes", LIMITS.maxTotalBytes.default);
  const maxFindings = numOpt(opts, "maxFindings", LIMITS.maxFindings.default);
  const follow = opts["symlinkPolicy"] === "follow-within-root";
  const rules = want.has("static") || want.has("config") ? loadRules() : [];

  const raw: RawFinding[] = [];
  const depFiles: DependencyFile[] = [];
  const allRels: string[] = [];
  let filesScanned = 0;
  let bytesScanned = 0;
  let capHit = false;
  let lastPost = 0;
  const progress = (force: boolean): void => {
    const t = Date.now();
    if (!force && t - lastPost < 25) return;
    lastPost = t;
    post({ type: "progress", filesScanned, bytesScanned, findingsSoFar: raw.length });
  };

  const walkOpts = {
    respectGitignore: opts["respectGitignore"] !== false,
    includeGlobs: (opts["includeGlobs"] as string[] | undefined) ?? [],
    excludeGlobs: (opts["excludeGlobs"] as string[] | undefined) ?? [],
    symlinkPolicy: follow ? ("follow-within-root" as const) : ("skip" as const),
    maxFiles,
    signal: abortController.signal,
  };
  const it = walk(spec.repoPath, walkOpts, warnings);
  for (;;) {
    if (checkAbort()) break;
    const n = it.next();
    if (n.done) {
      if (n.value.truncated) capHit = true;
      break;
    }
    const { abs, rel } = n.value;
    allRels.push(rel);
    filesScanned++;
    const file = readFileSafe(abs, rel, { maxFileBytes, warnings, signal: abortController.signal, allowSymlink: follow });
    if (file === undefined || file.aborted) {
      progress(false);
      continue;
    }
    bytesScanned += Buffer.byteLength(file.content, "utf8");
    const secretRaws: string[] = [];
    if (want.has("secret")) {
      for (const m of scanSecrets(rel, file.content)) {
        secretRaws.push(m.raw);
        const evidence = normalize(m.ruleId === "SEC-PRIVATE-KEY" ? redactPem(m.raw) : redact(m.raw), m.raw);
        raw.push({
          ruleId: m.ruleId, scanner: "secret", title: SECRET_TITLES[m.ruleId] ?? "Secret in source",
          severity: m.severity, confidence: m.confidence, cwe: ["CWE-798"],
          location: { path: rel, line: m.line, column: m.column },
          evidence: sanitize(evidence, EVIDENCE_MAX),
          message: "A credential-like value is committed to the repository",
          remediation: "Remove the secret from the repository and rotate it",
        });
      }
    }
    const lines = rules.length > 0 || want.has("config") ? file.content.split("\n") : [];
    const lineText = (n1: number): string => (lines[n1 - 1] ?? "").replace(/\r$/, "");
    if (rules.length > 0) {
      for (const m of scanStatic(rel, file.content, rules, warnings, { warnMinified: false })) {
        // JSON rules with a CFG- prefix are configuration rules (design 4.3).
        const scanner = m.ruleId.startsWith("CFG-") ? "config" : "static";
        if (!want.has(scanner)) continue;
        raw.push({
          ruleId: m.ruleId, scanner, title: m.title, severity: m.severity, confidence: m.confidence,
          cwe: [m.cwe], location: { path: rel, line: m.line, column: m.column },
          evidence: safeEvidence(lineText(m.line), secretRaws),
          message: m.title, remediation: "Review the flagged code and apply the safer alternative",
        });
      }
    }
    if (want.has("config")) {
      for (const m of scanConfig(rel, file.content)) {
        const evidence = m.ruleId === "CFG-ENV-COMMITTED-001" ? rel.split("/").pop() ?? rel : lineText(m.line);
        raw.push({
          ruleId: m.ruleId, scanner: "config", title: m.title, severity: m.severity, confidence: m.confidence,
          cwe: [m.cwe], location: { path: rel, line: m.line, column: m.column },
          evidence: safeEvidence(evidence, secretRaws),
          message: m.title, remediation: "Fix the configuration or remove the file from version control",
        });
      }
    }
    if (want.has("dependency") && lockfileKind(rel) !== undefined) depFiles.push({ rel, content: file.content });
    progress(false);
    if (bytesScanned > maxTotalBytes) {
      capHit = true;
      break;
    }
  }

  if (want.has("dependency") && !checkAbort()) {
    checkLockfilesMissing(allRels, warnings);
    const depWarnings = new Warnings();
    let db: AdvisoryDb | undefined;
    if (spec.dbPath) {
      try {
        db = loadAdvisoryDb(spec.dbPath, { warnings: depWarnings });
      } catch (e) {
        if (!(e instanceof McpError)) throw e;
        db = undefined; // already reported by the submit path
      }
    }
    const online = opts["online"] === true;
    const deps = await scanDependencies(depFiles, {
      db,
      warnings,
      online,
      ...(online ? { createClient: () => createOsvClient() } : {}),
    });
    for (const d of deps) raw.push(d);
    // DB-level warnings (missing/stale) were reported at submit time; keep shard-level ones only.
    for (const w of depWarnings.list()) {
      if (w.code === "W_ADVISORY_DB_STALE") continue;
      for (let i = 0; i < w.count; i++) warnings.add(w.code, w.path);
    }
  }

  const deduped = dedupeFindings(assignIdentity(raw));
  const cut = truncateTopK(deduped, maxFindings);
  if (cut.truncated) capHit = true;
  progress(true);
  return {
    type: "done",
    findings: cut.findings,
    warnings: warnings.list(),
    filesScanned,
    bytesScanned,
    truncated: capHit,
    capHit,
    aborted: abortController.signal.aborted,
    threadId,
  };
}

if (!isMainThread && parentPort) {
  const port = parentPort;
  runScan(workerData as RunSpec, (m) => port.postMessage(m)).then(
    (done) => port.postMessage(done),
    (err: unknown) => {
      throw err;
    },
  );
}
