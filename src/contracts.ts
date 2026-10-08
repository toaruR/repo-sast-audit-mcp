import { readFileSync } from "node:fs";
import { Ajv, type ErrorObject, type ValidateFunction } from "ajv";
import { assetPath } from "./assets.js";
import { LIMITS } from "./constants.js";

// Tool contracts (design 3). Schemas live in schemas/defs.json ($id "d") and schemas/tools.json.
export const TOOL_NAMES = ["scan_repository", "get_scan_status", "cancel_scan", "get_findings", "generate_report", "list_scanners", "update_advisory_db"] as const;

export type ToolName = (typeof TOOL_NAMES)[number];

interface ToolSchemas {
  input: Record<string, unknown>;
  output: Record<string, unknown>;
}

export interface ToolValidators {
  input: ValidateFunction;
  output: ValidateFunction;
}

function readJson(name: string): unknown {
  return JSON.parse(readFileSync(assetPath("schemas", name), "utf8"));
}

export function createAjv(): Ajv {
  // strict:false because defs.json keeps its entries at top level (d#/X) instead of under $defs.
  const ajv = new Ajv({ strict: false, allErrors: false });
  // x-limit: <name> expands to the 2.2 min/max of LIMITS[name].
  ajv.addKeyword({
    keyword: "x-limit",
    type: "integer",
    schemaType: "string",
    macro: (name: string) => {
      const lim = (LIMITS as Record<string, { min: number; max: number }>)[name];
      if (!lim) throw new Error(`unknown x-limit ${name}`);
      return { minimum: lim.min, maximum: lim.max };
    },
  });
  ajv.addSchema(readJson("defs.json") as object);
  return ajv;
}

export function loadContracts(ajv: Ajv = createAjv()): Record<ToolName, ToolValidators> {
  const tools = readJson("tools.json") as Record<string, ToolSchemas>;
  const out = {} as Record<ToolName, ToolValidators>;
  for (const name of TOOL_NAMES) {
    const t = tools[name];
    if (!t) throw new Error(`schemas/tools.json lacks ${name}`);
    out[name] = { input: ajv.compile(t.input), output: ajv.compile(t.output) };
  }
  return out;
}

export interface ValidationResult {
  valid: boolean;
  errors: ErrorObject[];
}

let cached: Record<ToolName, ToolValidators> | undefined;

function contracts(): Record<ToolName, ToolValidators> {
  cached ??= loadContracts();
  return cached;
}

export function validateInput(tool: ToolName, data: unknown): ValidationResult {
  const v = contracts()[tool].input;
  const valid = v(data) as boolean;
  return { valid, errors: valid ? [] : [...(v.errors ?? [])] };
}

export function validateOutput(tool: ToolName, data: unknown): ValidationResult {
  const v = contracts()[tool].output;
  const valid = v(data) as boolean;
  return { valid, errors: valid ? [] : [...(v.errors ?? [])] };
}
