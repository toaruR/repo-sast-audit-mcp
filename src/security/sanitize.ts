import { EVIDENCE_MAX } from "../constants.js";

// C0/C1 controls (incl. ESC 0x1B, but not \t), bidi marks/embeddings/isolates, zero-width, BOM, line/para separators.
const CONTROL_RE =
  /[\u0000-\u0008\u000A-\u001F\u007F-\u009F\u061C\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF]/;

function escChar(ch: string): string {
  switch (ch) {
    case "&":
      return "&amp;";
    case "<":
      return "&lt;";
    case ">":
      return "&gt;";
  }
  if (CONTROL_RE.test(ch)) {
    return "\\u" + ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0");
  }
  return ch;
}

/**
 * Escape untrusted repo text so it is inert data: <>& become entities, control/bidi/ANSI
 * characters become visible \uXXXX escapes. Output is cut (on escape boundaries) to max chars.
 */
export function sanitize(input: string, max: number = EVIDENCE_MAX): string {
  let out = "";
  for (const ch of input) {
    const e = escChar(ch);
    if (out.length + e.length > max) break;
    out += e;
  }
  return out;
}
