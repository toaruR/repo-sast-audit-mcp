import { GET_FINDINGS_DEFAULT_INCLUDE_EVIDENCE, GET_FINDINGS_DEFAULT_LIMIT } from "../constants.js";
import { validateInput } from "../contracts.js";
import { UNTRUSTED_FIELDS, makeErrorEnvelope, makeResultEnvelope } from "../envelope.js";
import { McpError } from "../errors.js";
import type { Finding } from "../findings/identity.js";
import type { Job } from "../jobs/jobManager.js";
import { decodeCursor, encodeCursor } from "./cursor.js";

/** What get_findings needs from the job registry (JobManager satisfies it). */
export interface FindingsSource {
  getJob(scanId: string): Pick<Job, "scanId" | "state" | "findings" | "generation"> | undefined;
}

interface FindingsFilter {
  minSeverity?: Finding["severity"];
  scanners?: string[];
  ruleIds?: string[];
  cwe?: string[];
  pathPrefix?: string;
}

interface GetFindingsArgs {
  scanId: string;
  cursor?: string;
  limit?: number;
  includeEvidence?: boolean;
  filter?: FindingsFilter;
}

const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;

/** AND across filter keys, OR within one list. */
function matches(f: Finding, flt: FindingsFilter): boolean {
  if (flt.minSeverity !== undefined && SEV_RANK[f.severity] < SEV_RANK[flt.minSeverity]) return false;
  if (flt.scanners !== undefined && !flt.scanners.includes(f.scanner)) return false;
  if (flt.ruleIds !== undefined && !flt.ruleIds.includes(f.ruleId)) return false;
  if (flt.cwe !== undefined && !f.cwe.some((c) => flt.cwe?.includes(c))) return false;
  if (flt.pathPrefix !== undefined && !f.location.path.startsWith(flt.pathPrefix)) return false;
  return true;
}

/** get_findings (design 3.4): cursor paging over the 5.3 order, pinned to a generation. */
export function getFindings(source: FindingsSource, args: unknown) {
  try {
    const v = validateInput("get_findings", args);
    if (!v.valid) {
      const e = v.errors[0];
      throw new McpError("E_INVALID_INPUT", `${e?.instancePath ?? ""} ${e?.message ?? "invalid input"}`.trim());
    }
    const a = args as GetFindingsArgs;
    const job = source.getJob(a.scanId);
    if (!job) throw new McpError("E_NOT_FOUND", "scan not found");
    const limit = a.limit ?? GET_FINDINGS_DEFAULT_LIMIT;
    const flt = a.filter;
    const all: readonly Finding[] = flt === undefined ? job.findings : job.findings.filter((f) => matches(f, flt));
    let offset = 0;
    if (a.cursor !== undefined) {
      const c = decodeCursor(a.cursor);
      if (c.scanId !== a.scanId) throw new McpError("E_INVALID_INPUT", "malformed cursor: belongs to another scan");
      if (c.generation !== job.generation) throw new McpError("E_CURSOR_STALE", "findings changed since the cursor was issued");
      if (c.offset > all.length) throw new McpError("E_INVALID_INPUT", "malformed cursor: offset out of range");
      offset = c.offset;
    }
    const includeEvidence = a.includeEvidence ?? GET_FINDINGS_DEFAULT_INCLUDE_EVIDENCE;
    const page = all.slice(offset, offset + limit).map((f) => (includeEvidence ? f : { ...f, evidence: "" }));
    const next = offset + limit;
    return makeResultEnvelope({
      scanId: job.scanId,
      state: job.state,
      complete: job.state === "completed",
      total: all.length,
      findings: page,
      nextCursor: next < all.length ? encodeCursor({ scanId: job.scanId, generation: job.generation, offset: next }) : null,
      untrusted: [...UNTRUSTED_FIELDS],
    });
  } catch (e) {
    if (e instanceof McpError) return makeErrorEnvelope(e.code, e.message);
    return makeErrorEnvelope("E_INTERNAL", "internal error");
  }
}
