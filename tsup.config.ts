import { defineConfig } from "tsup";

export default defineConfig({
  // Single entry; the package is small enough that bundling everything
  // through index keeps the dist tidy and the published surface
  // honest. Subpath imports are intentionally not part of the public
  // API in v0.1.
  entry: ["src/index.ts"],

  // Dual ESM + CJS so consumers on either module system can import
  // without a wrapper. The `exports` map in package.json points each
  // resolver at the right artifact.
  format: ["esm", "cjs"],

  // Type declarations alongside the JS so TypeScript users don't need
  // a separate @types package.
  dts: true,

  sourcemap: true,
  clean: true,

  // Target Node 18 — when native fetch landed and is the floor we
  // depend on. Older runtimes need a polyfill; we don't ship one.
  target: "es2022",

  // No external runtime deps: tsup doesn't need to externalize
  // anything, since `node:crypto` is built-in. Keep this empty so a
  // future accidental dep import shows up in the bundle and gets
  // caught in CI.
  external: [],
});
