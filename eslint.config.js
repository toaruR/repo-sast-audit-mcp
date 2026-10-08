import tseslint from "typescript-eslint";

const BAN_IMPORTS = [
  { name: "child_process", message: "BANNED: child_process is forbidden" },
  { name: "node:child_process", message: "BANNED: child_process is forbidden" },
  { name: "vm", message: "BANNED: node:vm is forbidden" },
  { name: "node:vm", message: "BANNED: node:vm is forbidden" },
];
const NET = ["http", "https", "http2", "net", "tls", "dgram", "dns"].flatMap((m) => [m, `node:${m}`]);
const FS = ["fs", "fs/promises", "node:fs", "node:fs/promises"];

const BAN_SYNTAX = [
  { selector: "ImportExpression", message: "BANNED: dynamic import() is forbidden" },
  { selector: "CallExpression[callee.name='eval']", message: "BANNED: eval is forbidden" },
  { selector: "CallExpression[callee.name='require']", message: "BANNED: require() is forbidden" },
];
const ENV_SYNTAX = {
  selector: "MemberExpression[object.name='process'][property.name='env']",
  message: "BANNED: process.env only allowed in src/constants.ts",
};

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**"] },
  ...tseslint.configs.recommended,
  {
    files: ["**/*.ts"],
    rules: {
      "no-restricted-imports": ["error", { paths: BAN_IMPORTS }],
      "no-restricted-syntax": ["error", ...BAN_SYNTAX, ENV_SYNTAX],
    },
  },
  {
    files: ["src/constants.ts"],
    rules: { "no-restricted-syntax": ["error", ...BAN_SYNTAX] },
  },
  {
    files: ["src/**/*.ts"],
    ignores: ["src/report/writer.ts", "src/net/osvClient.ts", "src/constants.ts"],
    rules: {
      "no-restricted-imports": ["error", { paths: [
        ...BAN_IMPORTS,
        ...NET.map((name) => ({ name, message: "BANNED: network only in src/net/osvClient.ts" })),
      ] }],
    },
  },
  {
    files: ["src/net/osvClient.ts"],
    rules: { "no-restricted-imports": ["error", { paths: [
      ...BAN_IMPORTS,
      ...FS.map((name) => ({ name, message: "BANNED: fs not allowed here" })),
    ] }] },
  },
  {
    // Tests and fixtures may spawn processes, read env, and use require/any (security bans target src/).
    files: ["test/**/*.{ts,cjs}"],
    rules: {
      "no-restricted-imports": "off",
      "no-restricted-syntax": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-require-imports": "off",
      "@typescript-eslint/no-unused-vars": "off",
    },
  },
);
