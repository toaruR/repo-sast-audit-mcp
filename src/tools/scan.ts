import { DEFAULT_OPTIONS, ENV, readEnv, DEFAULT_FORCE, LIMITS } from "../constants.js";
import { validateInput } from "../contracts.js";
import { makeErrorEnvelope, makeResultEnvelope } from "../envelope.js";
import { McpError, type ErrorCode } from "../errors.js";
import { loadAdvisoryDb } from "../advisory/db.js";
import { Warnings } from "../pipeline/warnings.js";
import { ALL_SCANNERS, DEFAULT_REQUEST, type JobManager, type ScanRequest } from "../jobs/jobManager.js";
import { validateRepoDir, type FsPathOptions } from "../security/paths.js";

export interface ScanDeps {
  pathOptions?: FsPathOptions;
  /** Clock for the DB staleness check (defaults to the advisory module clock). */
  now?: number | string | Date;
  rulesetHash?: string;
  serverVersion?: string;
}

interface ScanArgs {
  repoPath: string;
  scanners?: string[];
  options?: Record<string, unknown> & { limits?: Record<string, unknown> };
  force?: boolean;
  waitMs?: number;
}

function networkAllowed(): boolean {
  const v = readEnv(ENV.ALLOW_NETWORK);
  return v === "1" || v === "true";
}

export function normalizeOptions(given: ScanArgs["options"]): Record<string, unknown> {
  const o = given ?? {};
  const out: Record<string, unknown> = {
    ...(DEFAULT_OPTIONS as unknown as Record<string, unknown>),
    ...o,
    limits: { ...DEFAULT_OPTIONS.limits, ...(o.limits ?? {}) },
  };
  return out;
}

/**
 * Step 4: the advisory DB matters only when the dependency scanner runs. Explicit
 * scanners=["dependency",...] with a missing/invalid DB is an error; with scanners omitted a
 * missing DB is only W_ADVISORY_DB_MISSING. Returns the manifest sha256 ("" when no DB).
 */
export function checkAdvisoryDb(
  scanners: readonly string[] | undefined,
  advisoryDbPath: string | undefined,
  warnings: Warnings,
  now?: number | string | Date,
): string {
  if (scanners !== undefined && !scanners.includes("dependency")) return "";
  const dir = advisoryDbPath ?? readEnv(ENV.ADVISORY_DB);
  try {
    if (dir === undefined || dir === "") throw new McpError("E_ADVISORY_DB_MISSING", "no advisory database configured");
    return loadAdvisoryDb(dir, now === undefined ? { warnings } : { warnings, now }).manifestSha256;
  } catch (e) {
    if (e instanceof McpError && e.code === "E_ADVISORY_DB_MISSING" && scanners === undefined) {
      warnings.add("W_ADVISORY_DB_MISSING");
      return "";
    }
    throw e;
  }
}

/** scan_repository: submit steps 1-7 (design 3.2) with a stub runner. */
export async function scanRepository(manager: JobManager, args: unknown, deps: ScanDeps = {}) {
  try {
    // 1 schema
    const v = validateInput("scan_repository", args);
    if (!v.valid) {
      const e = v.errors[0];
      throw new McpError("E_INVALID_INPUT", `${e?.instancePath ?? ""} ${e?.message ?? "invalid input"}`.trim());
    }
    const a = args as ScanArgs;
    // 2 path
    const real = validateRepoDir(a.repoPath, deps.pathOptions);
    const options = normalizeOptions(a.options);
    // 3 network flag
    if (options["online"] === true && !networkAllowed()) {
      throw new McpError("E_NETWORK_DISABLED", `online scans need ${ENV.ALLOW_NETWORK}=1`);
    }
    // 4 DB check
    const warnings = new Warnings();
    const dbManifestSha256 = checkAdvisoryDb(a.scanners, options["advisoryDbPath"] as string | undefined, warnings, deps.now);
    const req: ScanRequest = {
      scanners: a.scanners ?? ALL_SCANNERS,
      options,
      dbManifestSha256,
      rulesetHash: deps.rulesetHash ?? DEFAULT_REQUEST.rulesetHash,
      serverVersion: deps.serverVersion ?? DEFAULT_REQUEST.serverVersion,
    };
    // 5-7 reuse, capacity, create
    const { job, reused } = manager.submitRequest(
      real,
      req,
      a.force ?? DEFAULT_FORCE,
      warnings.list(),
      (options["advisoryDbPath"] as string | undefined) ?? (readEnv(ENV.ADVISORY_DB) || undefined),
    );
    const waitMs = a.waitMs ?? LIMITS.waitMs.default;
    if (waitMs > 0 && job.state !== "completed") {
      await Promise.race([job.done, new Promise<void>((r) => setTimeout(r, waitMs).unref())]);
    }
    return makeResultEnvelope({
      scanId: job.scanId,
      state: job.state,
      requestKey: job.requestKey,
      reused,
      warnings: job.warnings,
      repoRealPath: real,
      progress: { ...job.progress },
      ...(job.summary ? { summary: job.summary } : {}),
    });
  } catch (e) {
    if (e instanceof McpError) return makeErrorEnvelope(e.code, e.message);
    return makeErrorEnvelope("E_INTERNAL" satisfies ErrorCode, "internal error");
  }
}
