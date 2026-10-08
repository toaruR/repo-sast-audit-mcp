// Deterministic lockfile text builders (LF only, stable key order).
export interface NpmPkg {
  name: string;
  version: string;
}

/** package-lock.json (lockfileVersion 3): the "version" line of the first package is line 6. */
export function npmLockfile(project: string, pkgs: readonly NpmPkg[]): string {
  const lines = ["{", `  "name": "${project}",`, '  "lockfileVersion": 3,', '  "packages": {'];
  pkgs.forEach((p, i) => {
    const comma = i < pkgs.length - 1 ? "," : "";
    lines.push(`    "node_modules/${p.name}": {`, `      "version": "${p.version}"`, `    }${comma}`);
  });
  lines.push("  }", "}");
  return lines.join("\n") + "\n";
}

/** requirements.txt with `==` pins, one per line. */
export function requirementsTxt(pins: readonly NpmPkg[]): string {
  return pins.map((p) => `${p.name}==${p.version}`).join("\n") + "\n";
}
