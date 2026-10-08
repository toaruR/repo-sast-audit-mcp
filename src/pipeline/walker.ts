import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { GLOB_LEN, GLOB_N, MAX_DEPTH } from "../constants.js";
import { McpError } from "../errors.js";
import { Warnings } from "./warnings.js";

interface Ignore {
  ignores(p: string): boolean;
  add(patterns: string): Ignore;
}
type Matcher = (p: string) => boolean;
const loadCjs = createRequire(import.meta.url);
const ignore = loadCjs("ignore") as () => Ignore;
const picomatch = loadCjs("picomatch") as (glob: string | string[], o?: Record<string, unknown>) => Matcher;

export function compileGlobs(globs: readonly string[]): Matcher {
  if (globs.length === 0) return () => false;
  return picomatch([...globs], { dot: true });
}

/** Throws E_INVALID_INPUT when more than GLOB_N globs or any glob longer than GLOB_LEN. */
export function validateGlobs(globs: readonly string[], name: string): void {
  if (globs.length > GLOB_N) throw new McpError("E_INVALID_INPUT", `${name} has more than ${GLOB_N} entries`);
  for (const g of globs) {
    if (typeof g !== "string" || g.length > GLOB_LEN) {
      throw new McpError("E_INVALID_INPUT", `${name} entry longer than ${GLOB_LEN} characters`);
    }
  }
}

export interface WalkOptions {
  respectGitignore?: boolean;
  /** Un-skips node_modules when an entry matches it; does not filter other files. */
  includeGlobs?: readonly string[];
  excludeGlobs?: readonly string[];
  symlinkPolicy?: "skip" | "follow-within-root";
  maxFiles?: number;
  signal?: AbortSignal;
  maxDepth?: number;
}

export interface WalkEntry {
  /** Absolute path. */
  abs: string;
  /** Path relative to the root, forward slashes. */
  rel: string;
}

export interface WalkResult {
  aborted: boolean;
  /** True when the maxFiles cap stopped the walk. */
  truncated: boolean;
}

const SKIP_DIRS = new Set([".git", "node_modules", ".sast-audit"]);

/** UTF-8 byte order equals code point order. */
function cpCompare(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function isInside(root: string, target: string): boolean {
  const win = process.platform === "win32";
  const rel = path.relative(win ? root.toLowerCase() : root, win ? target.toLowerCase() : target);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

interface IgnoreScope {
  base: string;
  ig: Ignore;
}

const EXPECTED_FS_ERRORS = new Set(["ENOENT", "ENOTDIR", "EACCES", "EPERM", "ELOOP"]);
const PERMISSION_FS_ERRORS = new Set(["EACCES", "EPERM", "EISDIR", "ELOOP"]);

function errnoCode(e: unknown): string | undefined {
  return typeof e === "object" && e !== null ? (e as NodeJS.ErrnoException).code : undefined;
}

/** True for expected filesystem races/denials; unexpected errors are rethrown. */
function expectedFsError(e: unknown): boolean {
  const c = errnoCode(e);
  return c !== undefined && EXPECTED_FS_ERRORS.has(c);
}

function loadGitignore(dir: string, rel: string, warnings: Warnings): IgnoreScope | undefined {
  try {
    const text = fs.readFileSync(path.join(dir, ".gitignore"), "utf8");
    return { base: rel, ig: ignore().add(text) };
  } catch (e) {
    const c = errnoCode(e);
    if (c === "ENOENT" || c === "ENOTDIR") return undefined; // no .gitignore here
    if (c !== undefined && PERMISSION_FS_ERRORS.has(c)) {
      warnings.add("W_PERMISSION_DENIED", rel === "" ? ".gitignore" : `${rel}/.gitignore`);
      return undefined;
    }
    throw e;
  }
}

type Kind = "dir" | "file" | "other";

/**
 * Depth-first walk in code-point order of full relative paths (directories sort as `name/`).
 * Yields regular files only. Warnings are recorded in `warnings`.
 */
export function* walk(
  root: string,
  opts: WalkOptions,
  warnings: Warnings,
): Generator<WalkEntry, WalkResult> {
  const includeGlobs = opts.includeGlobs ?? [];
  const excludeGlobs = opts.excludeGlobs ?? [];
  validateGlobs(includeGlobs, "includeGlobs");
  validateGlobs(excludeGlobs, "excludeGlobs");
  const maxDepth = opts.maxDepth ?? MAX_DEPTH;
  const maxFiles = opts.maxFiles ?? Number.POSITIVE_INFINITY;
  const respectGitignore = opts.respectGitignore ?? true;
  const follow = opts.symlinkPolicy === "follow-within-root";
  const signal = opts.signal;
  const matchesInclude = compileGlobs(includeGlobs);
  const matchesExclude = compileGlobs(excludeGlobs);
  const realRoot = fs.realpathSync(root);
  const visited = new Set<string>();
  const devIno = (p: string): string | undefined => {
    try {
      const st = fs.statSync(p, { bigint: true });
      return `${st.dev}:${st.ino}`;
    } catch (e) {
      if (expectedFsError(e)) return undefined;
      throw e;
    }
  };
  if (follow) {
    const k = devIno(root);
    if (k !== undefined) visited.add(k);
  }
  let emitted = 0;
  let truncated = false;

  function ignored(scopes: readonly IgnoreScope[], rel: string, isDir: boolean): boolean {
    for (const s of scopes) {
      const sub = s.base === "" ? rel : rel.slice(s.base.length + 1);
      if (s.ig.ignores(isDir ? `${sub}/` : sub)) return true;
    }
    return false;
  }

  function dirFiltered(scopes: readonly IgnoreScope[], name: string, rel: string): boolean {
    if (SKIP_DIRS.has(name) && !(name === "node_modules" && (matchesInclude(rel) || matchesInclude(`${rel}/`)))) return true;
    if (respectGitignore && ignored(scopes, rel, true)) return true;
    return matchesExclude(rel) || matchesExclude(`${rel}/`);
  }

  /** Classify a symlink target without reading its content; undefined means skip (warning recorded). */
  function resolveLink(abs: string, rel: string): Kind | undefined {
    let real: string;
    try {
      real = fs.realpathSync(abs);
    } catch (e) {
      if (!expectedFsError(e)) throw e;
      warnings.add("W_SYMLINK_SKIPPED", rel);
      return undefined;
    }
    if (!isInside(realRoot, real)) {
      warnings.add("W_SYMLINK_ESCAPE", rel);
      return undefined;
    }
    let st: fs.Stats;
    try {
      st = fs.statSync(real);
    } catch (e) {
      if (!expectedFsError(e)) throw e;
      warnings.add("W_SYMLINK_SKIPPED", rel);
      return undefined;
    }
    if (st.isDirectory()) {
      const k = devIno(real);
      if (k === undefined || visited.has(k)) {
        warnings.add("W_SYMLINK_SKIPPED", rel);
        return undefined;
      }
      visited.add(k);
      return "dir";
    }
    return st.isFile() ? "file" : "other";
  }

  /** Returns true when the walk must stop (abort or maxFiles). */
  function* visit(dir: string, rel: string, depth: number, scopes: readonly IgnoreScope[]): Generator<WalkEntry, boolean> {
    let scopesHere = scopes;
    if (respectGitignore) {
      const own = loadGitignore(dir, rel, warnings);
      if (own) scopesHere = [...scopes, own];
    }
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      if (!expectedFsError(e)) throw e;
      warnings.add("W_PERMISSION_DENIED", rel === "" ? undefined : rel);
      return false;
    }
    const keyed = entries.map((e) => ({ e, key: e.isDirectory() ? `${e.name}/` : e.name }));
    keyed.sort((a, b) => cpCompare(a.key, b.key));
    for (const { e } of keyed) {
      if (signal?.aborted) return true;
      const childRel = rel === "" ? e.name : `${rel}/${e.name}`;
      const abs = path.join(dir, e.name);
      let kind: Kind = e.isDirectory() ? "dir" : e.isFile() ? "file" : "other";
      if (e.isSymbolicLink()) {
        if (!follow) {
          warnings.add("W_SYMLINK_SKIPPED", childRel);
          continue;
        }
        // Skip lists apply to the link name before it is resolved.
        if (dirFiltered(scopesHere, e.name, childRel)) continue;
        const resolved = resolveLink(abs, childRel);
        if (resolved === undefined) continue;
        kind = resolved;
      } else if (kind === "dir") {
        if (dirFiltered(scopesHere, e.name, childRel)) continue;
        if (follow) {
          const k = devIno(abs);
          if (k !== undefined) visited.add(k);
        }
      }
      if (kind === "dir") {
        if (depth + 1 > maxDepth) {
          warnings.add("W_MAX_DEPTH", childRel);
          continue;
        }
        const stop = yield* visit(abs, childRel, depth + 1, scopesHere);
        if (stop) return true;
        continue;
      }
      if (kind !== "file") continue;
      if (respectGitignore && ignored(scopesHere, childRel, false)) continue;
      if (matchesExclude(childRel)) continue;
      if (signal?.aborted) return true;
      if (emitted >= maxFiles) {
        truncated = true;
        warnings.add("W_MAX_FILES");
        return true;
      }
      emitted++;
      yield { abs, rel: childRel };
    }
    return false;
  }

  const stopped = yield* visit(root, "", 0, []);
  return { aborted: stopped && !truncated, truncated };
}
