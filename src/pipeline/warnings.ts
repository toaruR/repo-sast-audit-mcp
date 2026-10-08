// Warning catalogue (design 4 and 9). Warnings are aggregated per (code, path) with a count.
export const WARNING_CODES = {
  W_SYMLINK_SKIPPED: "Symlink was not followed",
  W_SYMLINK_ESCAPE: "Symlink resolves outside the target and was not read",
  W_MAX_DEPTH: "Directory depth limit reached; deeper entries were not scanned",
  W_MAX_FILES: "maxFiles reached; remaining files were not scanned",
  W_PERMISSION_DENIED: "Entry could not be read",
  W_BINARY_SKIPPED: "Binary file skipped",
  W_NON_UTF8: "File is not valid UTF-8; decoded as latin1",
  W_MINIFIED_SKIPPED: "Minified line skipped",
  W_FILE_TOO_LARGE: "File larger than maxFileBytes skipped",
  W_FILE_CHANGED: "File changed between listing and open; dropped",
  W_FILE_VANISHED: "File vanished during the scan",
  W_LOCKFILE_MALFORMED: "Lockfile could not be parsed",
  W_LOCKFILE_MISSING: "No lockfile found",
  W_UNPINNED_REQUIREMENT: "Requirement is not pinned with ==",
  W_UNCOMPARABLE_VERSION: "Version could not be compared with advisory ranges",
  W_ADVISORY_DB_MISSING: "Advisory database is missing",
  W_ADVISORY_DB_STALE: "Advisory database is stale",
  W_ADVISORY_DB_INVALID_SHARD: "Advisory shard is invalid and was ignored",
  W_RULE_TIMEBUDGET: "Per-file rule time budget exceeded",
} as const;

export type WarningCode = keyof typeof WARNING_CODES;

export interface Warning {
  code: WarningCode;
  message: string;
  path?: string;
  count: number;
}

export class Warnings {
  private readonly map = new Map<string, Warning>();

  add(code: WarningCode, path?: string): void {
    const key = `${code}\n${path ?? ""}`;
    const cur = this.map.get(key);
    if (cur) {
      cur.count++;
      return;
    }
    const w: Warning = { code, message: WARNING_CODES[code], count: 1 };
    if (path !== undefined) w.path = path;
    this.map.set(key, w);
  }

  /** Sorted by (code, path) so output is deterministic. */
  list(): Warning[] {
    return [...this.map.values()].sort((a, b) => {
      const ka = `${a.code}\n${a.path ?? ""}`;
      const kb = `${b.code}\n${b.path ?? ""}`;
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
  }

  count(code: WarningCode): number {
    let n = 0;
    for (const w of this.map.values()) if (w.code === code) n += w.count;
    return n;
  }
}
