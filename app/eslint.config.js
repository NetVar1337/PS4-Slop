// app/eslint.config.js
// Flat config: JS + TypeScript recommended, React hooks rules, and Prettier
// owning formatting (eslint-config-prettier switches off stylistic rules)

import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    // src-tauri is Rust (owned by the Tauri crate); dist / target are build output
    ignores: ["dist/**", "node_modules/**", "src-tauri/**", "coverage/**"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: { globals: globals.browser },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/consistent-type-imports": ["error", { fixStyle: "inline-type-imports" }],
      eqeqeq: ["error", "always"],
      "no-console": ["error", { allow: ["warn", "error"] }],
    },
  },
  {
    files: ["scripts/**/*.{js,mjs}", "*.config.{js,ts}", "eslint.config.js"],
    languageOptions: { globals: globals.node },
  },
  {
    files: ["scripts/**/*.{ts,tsx}"],
    languageOptions: { globals: globals.browser },
  },
  prettier,
);
