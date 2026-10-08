import { McpError } from "../errors.js";
import { scanSecrets } from "../scanners/secret.js";
import { leaksSubstring } from "./redact.js";

/**
 * Output guard (G3): throws E_INTERNAL if the output string contains a secret matched by the
 * SEC-* patterns, or a LEAK_SUBSTR-char substring of any registered raw secret.
 * The message never echoes secret material.
 */
export function assertNoSecrets(output: string, registered: Iterable<string> = []): void {
  for (const raw of registered) {
    if (leaksSubstring(output, raw)) {
      throw new McpError("E_INTERNAL", "output guard: registered secret material detected in output");
    }
  }
  const hits = scanSecrets("output", output);
  if (hits.length > 0) {
    throw new McpError("E_INTERNAL", `output guard: secret pattern ${hits[0]?.ruleId ?? ""} detected in output`);
  }
}
