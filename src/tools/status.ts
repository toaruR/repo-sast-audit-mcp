import { validateInput } from "../contracts.js";
import { makeErrorEnvelope, makeResultEnvelope } from "../envelope.js";
import { isRetryable, McpError } from "../errors.js";
import type { JobManager } from "../jobs/jobManager.js";

/** get_scan_status (design 3.3). Unknown or evicted scanId => E_NOT_FOUND. */
export function getScanStatus(manager: JobManager, args: unknown) {
  try {
    const v = validateInput("get_scan_status", args);
    if (!v.valid) {
      const e = v.errors[0];
      throw new McpError("E_INVALID_INPUT", `${e?.instancePath ?? ""} ${e?.message ?? "invalid input"}`.trim());
    }
    const { scanId } = args as { scanId: string };
    const job = manager.getJob(scanId);
    if (!job) throw new McpError("E_NOT_FOUND", "scan not found");
    const st = manager.getStatus(scanId);
    const out: Record<string, unknown> = {
      scanId,
      state: job.state,
      progress: { ...(st?.progress ?? job.progress) },
      cancelRequested: job.cancelRequested,
      truncated: job.truncated,
      durationMs: job.durationMs,
      warnings: job.warnings,
    };
    if (job.summary) out["summary"] = job.summary;
    if (job.error !== undefined) {
      out["error"] = { code: job.error, message: job.error, retryable: isRetryable(job.error) };
    }
    return makeResultEnvelope(out);
  } catch (e) {
    if (e instanceof McpError) return makeErrorEnvelope(e.code, e.message);
    return makeErrorEnvelope("E_INTERNAL", "internal error");
  }
}

/** cancel_scan (design 3.3): queued cancels at once, running sets cancelRequested, terminal is a no-op. */
export function cancelScan(manager: JobManager, args: unknown) {
  try {
    const v = validateInput("cancel_scan", args);
    if (!v.valid) {
      const e = v.errors[0];
      throw new McpError("E_INVALID_INPUT", `${e?.instancePath ?? ""} ${e?.message ?? "invalid input"}`.trim());
    }
    const { scanId } = args as { scanId: string };
    const r = manager.cancel(scanId);
    if (!r) throw new McpError("E_NOT_FOUND", "scan not found");
    return makeResultEnvelope({ scanId, state: r.state, cancelRequested: r.cancelRequested });
  } catch (e) {
    if (e instanceof McpError) return makeErrorEnvelope(e.code, e.message);
    return makeErrorEnvelope("E_INTERNAL", "internal error");
  }
}
