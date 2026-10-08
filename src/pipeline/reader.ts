import fs from "node:fs";
import { ABORT_CHECK_LINES, BINARY_PROBE_BYTES, LINE_MAX } from "../constants.js";
import type { Warnings } from "./warnings.js";

export interface ReadOptions {
  maxFileBytes: number;
  warnings: Warnings;
  signal?: AbortSignal;
  /** Compare against stat() instead of lstat() (symlinkPolicy follow-within-root). */
  allowSymlink?: boolean;
  /** Test seam: replaces fs.openSync. */
  openSync?: (p: string, flags: string) => number;
  /** Test seam: replaces fs.closeSync. */
  closeSync?: (fd: number) => void;
}

export interface ReadResult {
  content: string;
  /** True when the content was decoded as latin1. */
  nonUtf8: boolean;
  /** 1-based numbers of lines longer than LINE_MAX. */
  minifiedLines: number[];
  lineCount: number;
  /** True when an abort stopped line processing; content is then partial-free (empty). */
  aborted: boolean;
}

function errCode(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException | undefined)?.code;
}

/**
 * Reads one listed file safely. Returns undefined when the file is skipped (a warning
 * is recorded under `rel`). Never throws for expected per-file failures.
 */
export function readFileSafe(abs: string, rel: string, opts: ReadOptions): ReadResult | undefined {
  const { warnings, signal } = opts;
  if (signal?.aborted) return undefined;
  let fd: number | undefined;
  try {
    let listed: fs.BigIntStats;
    try {
      listed = opts.allowSymlink ? fs.statSync(abs, { bigint: true }) : fs.lstatSync(abs, { bigint: true });
    } catch (e) {
      handleErr(e, rel, warnings);
      return undefined;
    }
    if (!listed.isFile()) {
      warnings.add("W_FILE_CHANGED", rel);
      return undefined;
    }
    try {
      fd = (opts.openSync ?? fs.openSync)(abs, "r");
    } catch (e) {
      handleErr(e, rel, warnings);
      return undefined;
    }
    const st = fs.fstatSync(fd, { bigint: true });
    if (!st.isFile() || st.dev !== listed.dev || st.ino !== listed.ino) {
      warnings.add("W_FILE_CHANGED", rel);
      return undefined;
    }
    if (st.size > BigInt(opts.maxFileBytes)) {
      warnings.add("W_FILE_TOO_LARGE", rel);
      return undefined;
    }
    const size = Number(st.size);
    const buf = Buffer.alloc(size);
    let got = 0;
    while (got < size) {
      const n = fs.readSync(fd, buf, got, size - got, got);
      if (n === 0) break;
      got += n;
    }
    const data = got === size ? buf : buf.subarray(0, got);
    if (data.subarray(0, BINARY_PROBE_BYTES).includes(0)) {
      warnings.add("W_BINARY_SKIPPED", rel);
      return undefined;
    }
    let content: string;
    let nonUtf8 = false;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(data);
    } catch {
      content = data.toString("latin1");
      nonUtf8 = true;
      warnings.add("W_NON_UTF8", rel);
    }
    const minifiedLines: number[] = [];
    let lineNo = 0;
    let pos = 0;
    while (pos <= content.length) {
      if (lineNo % ABORT_CHECK_LINES === 0 && signal?.aborted) {
        return { content: "", nonUtf8, minifiedLines, lineCount: lineNo, aborted: true };
      }
      let end = content.indexOf("\n", pos);
      if (end < 0) end = content.length;
      lineNo++;
      if (end - pos > LINE_MAX) minifiedLines.push(lineNo);
      pos = end + 1;
    }
    if (minifiedLines.length > 0) warnings.add("W_MINIFIED_SKIPPED", rel);
    return { content, nonUtf8, minifiedLines, lineCount: lineNo, aborted: false };
  } catch (e) {
    handleErr(e, rel, warnings);
    return undefined;
  } finally {
    if (fd !== undefined) {
      try {
        (opts.closeSync ?? fs.closeSync)(fd);
      } catch (e) {
        // EBADF: descriptor already gone (close race) - nothing left to release.
        // Anything else is unexpected: record it without masking the read result.
        if (errCode(e) !== "EBADF") warnings.add("W_PERMISSION_DENIED", rel);
      }
    }
  }
}

function handleErr(e: unknown, rel: string, warnings: Warnings): void {
  const c = errCode(e);
  if (c === "ENOENT" || c === "ENOTDIR") warnings.add("W_FILE_VANISHED", rel);
  else if (c === "EACCES" || c === "EPERM") warnings.add("W_PERMISSION_DENIED", rel);
  else warnings.add("W_FILE_CHANGED", rel);
}
