import { McpError } from "../errors.js";

const SID = /^S-[0-9a-f]{12}-[0-9]+$/;
const UINT = /^(?:0|[1-9][0-9]*)$/;

export interface Cursor {
  scanId: string;
  generation: number;
  offset: number;
}

/** base64url(`scanId:generation:offset`) (design 3.4). */
export function encodeCursor(c: Cursor): string {
  return Buffer.from(`${c.scanId}:${c.generation}:${c.offset}`, "utf8").toString("base64url");
}

function bad(why: string): McpError {
  return new McpError("E_INVALID_INPUT", `malformed cursor: ${why}`);
}

/** Strict decode: canonical base64url, exactly 3 parts, valid scanId, unsigned integers. */
export function decodeCursor(cursor: string): Cursor {
  if (!/^[A-Za-z0-9_-]+$/.test(cursor)) throw bad("not base64url");
  const text = Buffer.from(cursor, "base64url").toString("utf8");
  if (Buffer.from(text, "utf8").toString("base64url") !== cursor) throw bad("not canonical base64url");
  const parts = text.split(":");
  if (parts.length !== 3) throw bad("expected 3 parts");
  const [scanId, gen, off] = parts as [string, string, string];
  if (!SID.test(scanId)) throw bad("invalid scanId");
  if (!UINT.test(gen) || !UINT.test(off)) throw bad("generation and offset must be unsigned integers");
  const generation = Number(gen);
  const offset = Number(off);
  if (!Number.isSafeInteger(generation) || !Number.isSafeInteger(offset)) throw bad("number out of range");
  return { scanId, generation, offset };
}
