import fs from "node:fs";
import { RE2 } from "re2-wasm";
import { z } from "zod";
import { assetPath } from "../assets.js";
import { RULEID_MAX } from "../constants.js";
import { McpError } from "../errors.js";

export const RULE_LANGUAGES = ["javascript", "python", "yaml", "github-actions", "dockerfile", "any"] as const;
export type RuleLanguage = (typeof RULE_LANGUAGES)[number];

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
const ConfidenceSchema = z.enum(["high", "medium", "low"]);

export const RuleSchema = z
  .object({
    id: z.string().min(1).max(RULEID_MAX).regex(/^[A-Z0-9][A-Z0-9-]*$/),
    title: z.string().min(1).max(200),
    languages: z.array(z.enum(RULE_LANGUAGES)).min(1),
    pattern: z.string().min(1),
    negativePattern: z.string().min(1).optional(),
    severity: SeveritySchema,
    confidence: ConfidenceSchema,
    cwe: z.string().regex(/^CWE-\d+$/),
    tests: z
      .object({
        shouldMatch: z.array(z.string()).min(1),
        shouldNotMatch: z.array(z.string()).min(1),
      })
      .strict(),
  })
  .strict();

export type Rule = z.infer<typeof RuleSchema>;

export const RuleFileSchema = z.object({ rules: z.array(RuleSchema) }).strict();

export interface CompiledRule extends Rule {
  re: RE2;
  neg?: RE2;
}

function compile(id: string, what: string, src: string): RE2 {
  try {
    return new RE2(src, "gu");
  } catch (e) {
    throw new McpError("E_RULE_INVALID", `rule ${id}: ${what} is not a valid RE2 pattern: ${(e as Error).message}`);
  }
}

function hit(re: RE2, text: string): boolean {
  re.lastIndex = 0;
  const m = re.exec(text);
  re.lastIndex = 0;
  return m !== null;
}

/** Line-level decision shared with the engine: pattern matches and negativePattern does not. */
export function ruleFires(r: CompiledRule, line: string): boolean {
  return hit(r.re, line) && !(r.neg !== undefined && hit(r.neg, line));
}

/** Validates (zod strict), compiles (RE2 only) and self-tests rules. Throws E_RULE_INVALID. */
export function parseRules(input: unknown): CompiledRule[] {
  const parsed = RuleFileSchema.safeParse(input);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new McpError("E_RULE_INVALID", `rule file invalid at ${issue?.path.join(".") ?? ""}: ${issue?.message ?? ""}`);
  }
  const seen = new Set<string>();
  const out: CompiledRule[] = [];
  for (const rule of parsed.data.rules) {
    if (seen.has(rule.id)) throw new McpError("E_RULE_INVALID", `duplicate rule id ${rule.id}`);
    seen.add(rule.id);
    const c: CompiledRule = { ...rule, re: compile(rule.id, "pattern", rule.pattern) };
    if (rule.negativePattern !== undefined) c.neg = compile(rule.id, "negativePattern", rule.negativePattern);
    for (const s of rule.tests.shouldMatch) {
      if (!ruleFires(c, s)) throw new McpError("E_RULE_INVALID", `rule ${rule.id}: shouldMatch sample does not match`);
    }
    for (const s of rule.tests.shouldNotMatch) {
      if (ruleFires(c, s)) throw new McpError("E_RULE_INVALID", `rule ${rule.id}: shouldNotMatch sample matches`);
    }
    out.push(c);
  }
  return out;
}

export const DEFAULT_RULES_FILE = assetPath("rules", "rules.json");

/** Loads and self-tests the rule file. Any failure is E_RULE_INVALID (startup exit 2). */
export function loadRules(file: string = DEFAULT_RULES_FILE): CompiledRule[] {
  let json: unknown;
  try {
    json = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    throw new McpError("E_RULE_INVALID", `cannot read rule file: ${(e as Error).message}`);
  }
  return parseRules(json);
}
