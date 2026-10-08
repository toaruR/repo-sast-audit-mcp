import { REPORT_DEFAULTS, REPORT_FORMATS } from "../constants.js";
import { validateInput } from "../contracts.js";
import { makeErrorEnvelope, makeResultEnvelope } from "../envelope.js";
import { McpError } from "../errors.js";
import { currentTime } from "../advisory/db.js";
import { sortFindings } from "../findings/sort.js";
import { buildSummary, DEFAULT_REQUEST, type Job } from "../jobs/jobManager.js";
import { renderJson, renderMarkdown, type ReportInput } from "../report/render.js";
import { renderSarif } from "../report/sarif.js";
import { writeReportFiles, type WriteOptions } from "../report/writer.js";
import { assertNoSecrets } from "../security/assertNoSecrets.js";
import { validateOutputDir, type FsPathOptions } from "../security/paths.js";

type Format = (typeof REPORT_FORMATS)[number];

/** What generate_report needs from the job registry (JobManager satisfies it). */
export interface ReportSource {
  getJob(
    scanId: string,
  ): Pick<Job, "scanId" | "repoPath" | "state" | "findings" | "warnings" | "truncated" | "summary"> | undefined;
}

export interface ReportDeps {
  pathOptions?: FsPathOptions;
  /** Overrides SAST_AUDIT_MCP_OUTPUT_ROOT. */
  outputRoot?: string;
  rulesetHash?: string;
  serverVersion?: string;
  writeOptions?: WriteOptions;
  /** Output guard run once per generated file before anything is written (G3). */
  assertNoSecrets?: (output: string) => void;
}

interface ReportArgs {
  scanId: string;
  formats?: Format[];
  outputDir?: string;
  allowWriteInsideTarget?: boolean;
  allowPartial?: boolean;
  includeEvidence?: boolean;
}

const FILE_NAMES: Record<Format, string> = { md: "report.md", json: "report.json", sarif: "report.sarif.json" };

/** generate_report (design 3.5): validate, check state, resolve output dir, render, write atomically. */
export function generateReport(source: ReportSource, args: unknown, deps: ReportDeps = {}) {
  try {
    const v = validateInput("generate_report", args);
    if (!v.valid) {
      const e = v.errors[0];
      throw new McpError("E_INVALID_INPUT", `${e?.instancePath ?? ""} ${e?.message ?? "invalid input"}`.trim());
    }
    const a = args as ReportArgs;
    const job = source.getJob(a.scanId);
    if (!job) throw new McpError("E_NOT_FOUND", "scan not found");
    const allowPartial = a.allowPartial ?? REPORT_DEFAULTS.allowPartial;
    const partial = job.state !== "completed";
    if (job.state === "queued" || job.state === "running") {
      return makeErrorEnvelope("E_SCAN_NOT_COMPLETE", "scan is still queued or running", true);
    }
    if (partial && !allowPartial) {
      return makeErrorEnvelope("E_SCAN_NOT_COMPLETE", `scan ended as ${job.state}; pass allowPartial to report partial results`, false);
    }
    const dir = validateOutputDir(job.repoPath, {
      ...(deps.pathOptions ?? {}),
      scanId: job.scanId,
      ...(a.outputDir !== undefined ? { outputDir: a.outputDir } : {}),
      allowWriteInsideTarget: a.allowWriteInsideTarget ?? REPORT_DEFAULTS.allowWriteInsideTarget,
      ...(deps.outputRoot !== undefined ? { outputRoot: deps.outputRoot } : {}),
    });

    const wanted = new Set<Format>(a.formats ?? REPORT_DEFAULTS.formats);
    const formats = REPORT_FORMATS.filter((f) => wanted.has(f));
    const includeEvidence = a.includeEvidence ?? REPORT_DEFAULTS.includeEvidence;
    const summary = job.summary ?? buildSummary(job.findings, job.truncated);
    const serverVersion = deps.serverVersion ?? DEFAULT_REQUEST.serverVersion;
    const sorted = sortFindings(job.findings);
    const input: ReportInput = {
      scanId: job.scanId,
      rulesetHash: deps.rulesetHash ?? DEFAULT_REQUEST.rulesetHash,
      generatedAt: new Date(currentTime()).toISOString(),
      state: job.state,
      partial,
      summary,
      findings: sorted,
      warnings: job.warnings,
    };
    const render: Record<Format, () => string> = {
      md: () => renderMarkdown(input, { includeEvidence }),
      json: () => renderJson(input, { includeEvidence }),
      sarif: () => renderSarif(sorted, serverVersion),
    };
    const contents = formats.map((f) => ({ format: f, name: FILE_NAMES[f], content: render[f]() }));
    const guard = deps.assertNoSecrets ?? ((t: string) => assertNoSecrets(t));
    for (const c of contents) guard(c.content);
    const written = writeReportFiles(
      dir,
      contents.map((c) => ({ name: c.name, content: c.content })),
      deps.writeOptions,
    );
    return makeResultEnvelope({
      scanId: job.scanId,
      outputDir: dir,
      files: written.map((w, i) => ({ format: contents[i]?.format, path: w.path, bytes: w.bytes, sha256: w.sha256 })),
      summary,
      partial,
    });
  } catch (e) {
    if (e instanceof McpError) return makeErrorEnvelope(e.code, e.message);
    return makeErrorEnvelope("E_INTERNAL", "internal error");
  }
}
