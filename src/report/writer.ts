import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { McpError } from "../errors.js";

/** Filesystem primitives used by the writer; tests replace single members to inject failures. */
export interface WriteOps {
  mkdirSync(dir: string): void;
  openSync(file: string, flags: string): number;
  writeSync(fd: number, data: Buffer): void;
  fsyncSync(fd: number): void;
  closeSync(fd: number): void;
  renameSync(from: string, to: string): void;
  unlinkSync(file: string): void;
}

export const defaultOps: WriteOps = {
  mkdirSync: (dir) => void fs.mkdirSync(dir, { recursive: true }),
  openSync: (file, flags) => fs.openSync(file, flags, 0o644),
  writeSync: (fd, data) => {
    let off = 0;
    while (off < data.length) off += fs.writeSync(fd, data, off, data.length - off);
  },
  fsyncSync: (fd) => fs.fsyncSync(fd),
  closeSync: (fd) => fs.closeSync(fd),
  renameSync: (a, b) => fs.renameSync(a, b),
  unlinkSync: (f) => fs.unlinkSync(f),
};

export interface ReportFileInput {
  /** Base file name inside the output directory (e.g. report.md). */
  name: string;
  content: string;
}

export interface WrittenFile {
  name: string;
  path: string;
  bytes: number;
  sha256: string;
}

export interface WriteOptions {
  ops?: Partial<WriteOps>;
  /** Temp name for a target file name (defaults to a unique `.<name>.<pid>.<random>.tmp`). */
  tmpName?: (name: string) => string;
}

function defaultTmpName(name: string): string {
  return `.${name}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
}

function code(e: unknown): string {
  return (e as NodeJS.ErrnoException | undefined)?.code ?? "UNKNOWN";
}

/**
 * The only module that writes report files (design 7): every file goes to a `wx` temp file, is
 * fsynced and closed; only then are the temps renamed over their targets in order. On any failure
 * the temp files that are still pending are removed (a pre-existing file is never touched) and
 * E_WRITE_FAILED (retryable) names the failed file. Files already renamed stay (partial set, F-11a).
 */
export function writeReportFiles(dir: string, files: readonly ReportFileInput[], options: WriteOptions = {}): WrittenFile[] {
  const ops: WriteOps = { ...defaultOps, ...options.ops };
  const tmpName = options.tmpName ?? defaultTmpName;
  const created: string[] = []; // temp files this call created and has not renamed
  const pending = new Map<string, string>(); // name -> tmp path
  const cleanupErrors: unknown[] = []; // unexpected cleanup failures, attached as cause of the thrown error
  const cleanup = (): void => {
    for (const t of created) {
      try {
        ops.unlinkSync(t);
      } catch (e) {
        if (code(e) !== "ENOENT") cleanupErrors.push(e); // ENOENT: already gone
      }
    }
    created.length = 0;
  };
  const fail = (name: string, step: string, e: unknown): never => {
    cleanup();
    throw new McpError("E_WRITE_FAILED", `could not ${step} ${name} (${code(e)})`, {
      cause: cleanupErrors.length > 0 ? new AggregateError([e, ...cleanupErrors], "cleanup failed") : e,
    });
  };

  try {
    ops.mkdirSync(dir);
  } catch (e) {
    fail("output directory", "create", e);
  }

  const out: WrittenFile[] = [];
  const data = files.map((f) => ({ ...f, buf: Buffer.from(f.content, "utf8") }));
  for (const f of data) {
    const tmp = path.join(dir, tmpName(f.name));
    let fd: number;
    try {
      fd = ops.openSync(tmp, "wx");
    } catch (e) {
      return fail(f.name, "open a temporary file for", e);
    }
    created.push(tmp);
    pending.set(f.name, tmp);
    try {
      ops.writeSync(fd, f.buf);
      ops.fsyncSync(fd);
    } catch (e) {
      try {
        ops.closeSync(fd);
      } catch (ce) {
        if (code(ce) !== "EBADF") cleanupErrors.push(ce); // EBADF: fd already closed
      }
      return fail(f.name, "write", e);
    }
    try {
      ops.closeSync(fd);
    } catch (e) {
      return fail(f.name, "close", e);
    }
  }

  for (const f of data) {
    const tmp = pending.get(f.name) as string;
    const target = path.join(dir, f.name);
    try {
      ops.renameSync(tmp, target);
    } catch (e) {
      return fail(f.name, "rename into place", e);
    }
    created.splice(created.indexOf(tmp), 1);
    out.push({
      name: f.name,
      path: target,
      bytes: f.buf.length,
      sha256: crypto.createHash("sha256").update(f.buf).digest("hex"),
    });
  }
  return out;
}
