import { XMLValidator } from "fast-xml-parser";
import { parse as parseToml } from "smol-toml";
import { parse as parseYaml } from "yaml";
import { LOCKFILE_MAX_BYTES } from "../constants.js";
import type { Warnings } from "../pipeline/warnings.js";

export interface LockPackage {
  ecosystem: string;
  name: string;
  version: string;
  /** 1-based line of the entry inside the lockfile. */
  line: number;
  path: string;
  confidence: "high" | "medium";
}

export type LockfileKind =
  | "package-lock.json"
  | "yarn.lock"
  | "pnpm-lock.yaml"
  | "poetry.lock"
  | "Cargo.lock"
  | "requirements.txt"
  | "go.sum"
  | "pom.xml";

const HIGH_KINDS: readonly string[] = [
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "poetry.lock",
  "Cargo.lock",
  "requirements.txt",
  "go.sum",
  "pom.xml",
];

export function lockfileKind(rel: string): LockfileKind | undefined {
  const base = rel.split(/[\\/]/).pop() ?? "";
  return HIGH_KINDS.includes(base) ? (base as LockfileKind) : undefined;
}

type Raw = { name: string; version: string; line: number };

function mk(
  rel: string,
  ecosystem: string,
  confidence: "high" | "medium",
  raws: readonly Raw[],
): LockPackage[] {
  // First occurrence of name@version wins (design 4.1: firstLine).
  const seen = new Set<string>();
  const out: LockPackage[] = [];
  for (const r of raws) {
    const k = `${r.name}@${r.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ ecosystem, name: r.name, version: r.version, line: r.line, path: rel, confidence });
  }
  return out;
}

const NPM_KEY = /^\s*"([^"]*)"\s*:\s*\{\s*$/;
const NPM_VERSION = /^\s*"version"\s*:\s*"([^"]+)"/;
const NPM_RESERVED = new Set(["packages", "dependencies", "requires", "engines", "bin", "funding"]);

function npmEntries(content: string): Raw[] {
  JSON.parse(content); // throws on malformed input
  const out: Raw[] = [];
  const lines = content.split("\n");
  let pending: string | undefined;
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i] ?? "";
    const k = NPM_KEY.exec(text);
    if (k) {
      const key = k[1] ?? "";
      const idx = key.lastIndexOf("node_modules/");
      const name = idx >= 0 ? key.slice(idx + "node_modules/".length) : key;
      pending = name === "" || NPM_RESERVED.has(name) ? undefined : name;
      continue;
    }
    const v = NPM_VERSION.exec(text);
    if (v && pending !== undefined) {
      out.push({ name: pending, version: v[1] ?? "", line: i + 1 });
      pending = undefined;
    }
  }
  return out;
}

function yarnEntries(content: string): Raw[] {
  const out: Raw[] = [];
  const lines = content.split("\n");
  let cur: { name: string; line: number } | undefined;
  for (let i = 0; i < lines.length; i++) {
    const text = (lines[i] ?? "").replace(/\r$/, "");
    if (text === "" || text.startsWith("#")) continue;
    if (!/^\s/.test(text)) {
      if (!text.endsWith(":")) throw new Error("yarn.lock: bad header");
      const first = (text.slice(0, -1).split(",")[0] ?? "").trim().replace(/^"|"$/g, "");
      const at = first.lastIndexOf("@");
      if (at <= 0) {
        cur = undefined; // e.g. __metadata
        continue;
      }
      cur = { name: first.slice(0, at), line: i + 1 };
      continue;
    }
    const v = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(text);
    if (v && cur) {
      out.push({ name: cur.name, version: v[1] ?? "", line: cur.line });
      cur = undefined;
    }
  }
  return out;
}

function pnpmEntries(content: string): Raw[] {
  parseYaml(content); // throws on malformed input
  const out: Raw[] = [];
  const lines = content.split("\n");
  let inPackages = false;
  for (let i = 0; i < lines.length; i++) {
    const text = (lines[i] ?? "").replace(/\r$/, "");
    if (/^\S/.test(text)) {
      inPackages = /^packages:\s*$/.test(text);
      continue;
    }
    if (!inPackages) continue;
    const m = /^ {2}['"]?\/?(.+?)['"]?:\s*(?:\{.*)?$/.exec(text);
    if (!m) continue;
    const spec = (m[1] ?? "").replace(/\(.*$/, "");
    const at = spec.lastIndexOf("@");
    if (at > 0) {
      out.push({ name: spec.slice(0, at), version: spec.slice(at + 1), line: i + 1 });
      continue;
    }
    // lockfile v5: /name/version
    const slash = spec.lastIndexOf("/");
    if (slash > 0) out.push({ name: spec.slice(0, slash), version: spec.slice(slash + 1), line: i + 1 });
  }
  return out;
}

function tomlEntries(content: string): Raw[] {
  parseToml(content); // throws on malformed input
  const out: Raw[] = [];
  const lines = content.split("\n");
  let cur: { name?: string; version?: string; line: number } | undefined;
  const flush = (): void => {
    if (cur?.name !== undefined && cur.version !== undefined) {
      out.push({ name: cur.name, version: cur.version, line: cur.line });
    }
    cur = undefined;
  };
  for (let i = 0; i < lines.length; i++) {
    const text = (lines[i] ?? "").replace(/\r$/, "");
    if (/^\s*\[\[package\]\]\s*$/.test(text)) {
      flush();
      cur = { line: i + 1 };
      continue;
    }
    if (/^\s*\[/.test(text)) {
      flush();
      continue;
    }
    if (!cur) continue;
    const kv = /^(name|version)\s*=\s*"([^"]*)"\s*$/.exec(text);
    if (kv) {
      if (kv[1] === "name") cur.name = kv[2] ?? "";
      else cur.version = kv[2] ?? "";
    }
  }
  flush();
  return out;
}

function requirementsEntries(rel: string, content: string, warnings: Warnings): Raw[] {
  const out: Raw[] = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const text = (lines[i] ?? "").replace(/\r$/, "").replace(/\s+#.*$/, "").trim();
    if (text === "" || text.startsWith("#") || text.startsWith("-")) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)\s*(?:;.*)?$/.exec(text);
    if (m) out.push({ name: m[1] ?? "", version: m[2] ?? "", line: i + 1 });
    else warnings.add("W_UNPINNED_REQUIREMENT", rel);
  }
  return out;
}

function goSumEntries(content: string): Raw[] {
  const out: Raw[] = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const text = (lines[i] ?? "").replace(/\r$/, "").trim();
    if (text === "") continue;
    const parts = text.split(/\s+/);
    if (parts.length !== 3) throw new Error("go.sum: bad line");
    const version = parts[1] ?? "";
    if (version.endsWith("/go.mod")) continue;
    out.push({ name: parts[0] ?? "", version, line: i + 1 });
  }
  return out;
}

function pomEntries(content: string): Raw[] {
  if (XMLValidator.validate(content) !== true) throw new Error("pom.xml: invalid XML");
  const out: Raw[] = [];
  const tag = (block: string, name: string): string | undefined => {
    const a = block.indexOf(`<${name}>`);
    if (a < 0) return undefined;
    const b = block.indexOf(`</${name}>`, a);
    if (b < 0) return undefined;
    return block.slice(a + name.length + 2, b).trim();
  };
  let pos = 0;
  let line = 1;
  let counted = 0;
  for (;;) {
    const a = content.indexOf("<dependency>", pos);
    if (a < 0) break;
    const b = content.indexOf("</dependency>", a);
    if (b < 0) break;
    for (let i = counted; i < a; i++) if (content.charCodeAt(i) === 10) line++;
    counted = a;
    const block = content.slice(a, b);
    const g = tag(block, "groupId");
    const art = tag(block, "artifactId");
    const v = tag(block, "version");
    if (g && art && v && !v.includes("${")) out.push({ name: `${g}:${art}`, version: v, line });
    pos = b;
  }
  return out;
}

const MANIFEST_LOCKS: ReadonlyArray<readonly [string, readonly string[]]> = [
  ["package.json", ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]],
  ["Cargo.toml", ["Cargo.lock"]],
  ["pyproject.toml", ["poetry.lock", "requirements.txt"]],
];

/** W_LOCKFILE_MISSING once per manifest whose directory holds none of its lockfiles. */
export function checkLockfilesMissing(rels: readonly string[], warnings: Warnings): void {
  const set = new Set(rels.map((r) => r.replace(/\\/g, "/")));
  for (const r of [...set].sort()) {
    const slash = r.lastIndexOf("/");
    const dir = slash < 0 ? "" : r.slice(0, slash + 1);
    const base = r.slice(dir.length);
    const entry = MANIFEST_LOCKS.find(([m]) => m === base);
    if (!entry) continue;
    if (!entry[1].some((l) => set.has(dir + l))) warnings.add("W_LOCKFILE_MISSING", r);
  }
}

/**
 * Parses a lockfile. Unparsable input yields W_LOCKFILE_MALFORMED and no packages;
 * a lockfile larger than LOCKFILE_MAX_BYTES is skipped with W_FILE_TOO_LARGE.
 */
export function parseLockfile(rel: string, content: string, warnings: Warnings): LockPackage[] {
  const kind = lockfileKind(rel);
  if (kind === undefined) return [];
  if (Buffer.byteLength(content, "utf8") > LOCKFILE_MAX_BYTES) {
    warnings.add("W_FILE_TOO_LARGE", rel);
    return [];
  }
  try {
    switch (kind) {
      case "package-lock.json":
        return mk(rel, "npm", "high", npmEntries(content));
      case "yarn.lock":
        return mk(rel, "npm", "high", yarnEntries(content));
      case "pnpm-lock.yaml":
        return mk(rel, "npm", "high", pnpmEntries(content));
      case "poetry.lock":
        return mk(rel, "PyPI", "high", tomlEntries(content));
      case "Cargo.lock":
        return mk(rel, "crates.io", "high", tomlEntries(content));
      case "requirements.txt":
        return mk(rel, "PyPI", "high", requirementsEntries(rel, content, warnings));
      case "go.sum":
        return mk(rel, "Go", "medium", goSumEntries(content));
      case "pom.xml":
        return mk(rel, "Maven", "medium", pomEntries(content));
    }
  } catch {
    warnings.add("W_LOCKFILE_MALFORMED", rel);
    return [];
  }
}
