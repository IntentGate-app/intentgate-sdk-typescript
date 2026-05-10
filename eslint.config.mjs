// Flat-config ESLint for the SDK. Strict TS rules; no rules
// specific to a particular runtime since the SDK targets both Node
// and (browser-fetch-equipped) edge runtimes.

import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";

export default [
  {
    ignores: ["dist/**", "node_modules/**", "coverage/**"],
  },
  {
    files: ["src/**/*.ts", "tests/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: "module",
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      // Allow leading-underscore for unused params; common in mocks.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // The SDK is small and the explicit any cases are localized in
      // the JSON parsing path, where they're guarded by isObject.
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
];
