import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ENV, PATH_MAX, readEnv } from "../constants.js";
import { McpError } from "../errors.js";

const RESERVED = new RegExp("^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$", "i");
const ABSOLUTE = /^(?:\/|[A-Za-z]:[\\/]|\\\\)/;

export function allowedRoots(): string[] {
  const env = readEnv(ENV.ALLOWED_ROOTS);
  if (env === undefined || env.trim() === "") return [path.resolve(process.cwd())];
  return env.split(path.delimiter).filter((s) => s !== "").map((s) => path.resolve(s));
}

function isInside(root: string, target: string): boolean {
  const win = process.platform === "win32";
  const r = win ? root.toLowerCase() : root;
  const t = win ? target.toLowerCase() : target;
  const rel = path.relative(r, t);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** String-level repoPath validation; performs no filesystem access. Returns the normalized absolute path. */
export function validateRepoPath(p: string, opts: { allowedRoots?: readonly string[] } = {}): string {
  if (typeof p !== "string" || p.length === 0) throw new McpError("E_INVALID_INPUT", "repoPath must be a non-empty string");
  if (p.includes("\0")) throw new McpError("E_INVALID_INPUT", "repoPath contains a NUL character");
  if (p.length > PATH_MAX) throw new McpError("E_INVALID_INPUT", `repoPath longer than ${PATH_MAX} characters`);
  if (!ABSOLUTE.test(p)) throw new McpError("E_INVALID_INPUT", "repoPath must be absolute");
  const segments = p.split(/[\\/]/);
  for (const seg of segments) {
    const stem = (seg.split(".")[0] ?? "").replace(/[ .]+$/, "");
    if (RESERVED.test(stem)) throw new McpError("E_INVALID_INPUT", "repoPath contains a reserved name");
  }
  if (segments.includes("..")) throw new McpError("E_PATH_TRAVERSAL", "repoPath contains a '..' segment");
  const resolved = path.resolve(p);
  const roots = (opts.allowedRoots ?? allowedRoots()).map((r) => path.resolve(r));
  if (!roots.some((r) => isInside(r, resolved))) {
    throw new McpError("E_PATH_TRAVERSAL", "repoPath is outside the allowed roots");
  }
  return resolved;
}

export interface FsPathOptions {
  allowedRoots?: readonly string[];
  /** Injectable directory-open probe (defaults to fs.opendirSync); used to map EACCES/EPERM. */
  opendirSync?: (p: string) => { closeSync(): void };
}

function probeDir(p: string, what: string, opts: FsPathOptions): void {
  const open = opts.opendirSync ?? ((x: string) => fs.opendirSync(x));
  try {
    open(p).closeSync();
  } catch (e) {
    const c = (e as NodeJS.ErrnoException).code;
    if (c === "EACCES" || c === "EPERM") throw new McpError("E_PERMISSION_DENIED", `${what} is not readable`);
    if (c === "ENOENT" || c === "ENOTDIR") throw new McpError("E_NOT_FOUND", `${what} not found`);
    throw new McpError("E_INTERNAL", `${what} could not be opened`);
  }
}

function realRoot(r: string): string {
  try {
    return fs.realpathSync(r);
  } catch (e) {
    const c = (e as NodeJS.ErrnoException).code;
    if (c !== "ENOENT" && c !== "ENOTDIR" && c !== "EACCES" && c !== "EPERM" && c !== "ELOOP") throw e;
    return path.resolve(r);
  }
}

/** Filesystem-level repoPath validation (realpath, allowed-root recheck, directory check, readability). Returns the real path. */
export function validateRepoDir(p: string, opts: FsPathOptions = {}): string {
  const resolved = validateRepoPath(p, opts);
  let real: string;
  try {
    real = fs.realpathSync(resolved);
  } catch (e) {
    const c = (e as NodeJS.ErrnoException).code;
    if (c === "EACCES" || c === "EPERM") throw new McpError("E_PERMISSION_DENIED", "repoPath is not readable");
    throw new McpError("E_NOT_FOUND", "repoPath not found");
  }
  let isDir = false;
  try {
    isDir = fs.statSync(real).isDirectory();
  } catch (e) {
    const c = (e as NodeJS.ErrnoException).code;
    if (c === "EACCES" || c === "EPERM") throw new McpError("E_PERMISSION_DENIED", "repoPath is not readable");
    throw new McpError("E_NOT_FOUND", "repoPath not found");
  }
  if (!isDir) throw new McpError("E_NOT_FOUND", "repoPath is not a directory");
  const roots = (opts.allowedRoots ?? allowedRoots()).map(realRoot);
  if (!roots.some((r) => isInside(r, real))) {
    throw new McpError("E_PATH_TRAVERSAL", "repoPath resolves outside the allowed roots");
  }
  probeDir(real, "repoPath", opts);
  return real;
}

/** realpath of the nearest existing ancestor joined with the not-yet-existing remainder. */
function realpathLoose(p: string): string {
  const rest: string[] = [];
  let cur = path.resolve(p);
  for (;;) {
    try {
      return path.join(fs.realpathSync(cur), ...rest.reverse());
    } catch (e) {
      const c = (e as NodeJS.ErrnoException).code;
      if (c === "EACCES" || c === "EPERM") throw new McpError("E_PERMISSION_DENIED", "outputDir is not readable");
      const parent = path.dirname(cur);
      if (parent === cur) return path.resolve(p);
      rest.push(path.basename(cur));
      cur = parent;
    }
  }
}

export interface OutputDirOptions extends FsPathOptions {
  scanId: string;
  outputDir?: string;
  allowWriteInsideTarget?: boolean;
  /** Overrides VULN_MCP_OUTPUT_ROOT / os.tmpdir()/repo-vuln-report. */
  outputRoot?: string;
}

/**
 * Resolve and validate the report output directory. `repoReal` is the realpath of the target.
 * Judged by realpath; performs no filesystem mutation. Returns the real (possibly not yet existing) path.
 */
export function validateOutputDir(repoReal: string, opts: OutputDirOptions): string {
  const outputRoot =
    opts.outputRoot ?? readEnv(ENV.OUTPUT_ROOT) ?? path.join(os.tmpdir(), "repo-vuln-report");
  const allow = opts.allowWriteInsideTarget === true;
  let candidate: string;
  if (opts.outputDir === undefined) {
    candidate = allow ? path.join(repoReal, ".vuln-report") : path.join(outputRoot, opts.scanId);
  } else {
    const o = opts.outputDir;
    if (typeof o !== "string" || o.length === 0) throw new McpError("E_INVALID_INPUT", "outputDir must be a non-empty string");
    if (o.includes("\0")) throw new McpError("E_INVALID_INPUT", "outputDir contains a NUL character");
    if (o.length > PATH_MAX) throw new McpError("E_INVALID_INPUT", `outputDir longer than ${PATH_MAX} characters`);
    if (!ABSOLUTE.test(o)) throw new McpError("E_INVALID_INPUT", "outputDir must be absolute");
    if (o.split(/[\/]/).includes("..")) throw new McpError("E_PATH_TRAVERSAL", "outputDir contains a '..' segment");
    candidate = o;
  }
  const real = realpathLoose(candidate);
  const target = realRoot(repoReal);
  if (isInside(real, target)) throw new McpError("E_OUTPUT_DIR_UNSAFE", "outputDir is the target or an ancestor of it");
  if (isInside(path.join(target, ".git"), real)) throw new McpError("E_OUTPUT_DIR_UNSAFE", "outputDir is under .git");
  if (isInside(target, real) && !allow) {
    throw new McpError("E_OUTPUT_DIR_UNSAFE", "outputDir is inside the target without allowWriteInsideTarget");
  }
  const roots = [...(opts.allowedRoots ?? allowedRoots()), outputRoot].map(realRoot);
  if (!roots.some((r) => isInside(r, real))) {
    throw new McpError("E_PATH_TRAVERSAL", "outputDir is outside the allowed roots");
  }
  // Probe nearest existing ancestor for readability before any write.
  let probe = real;
  while (!fs.existsSync(probe)) {
    const parent = path.dirname(probe);
    if (parent === probe) break;
    probe = parent;
  }
  if (fs.existsSync(probe)) probeDir(probe, "outputDir", opts);
  return real;
}
