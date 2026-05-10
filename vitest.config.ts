import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Tests are TypeScript ES modules; vitest handles transpilation
    // out of the box. Source is referenced directly (no need to
    // `npm run build` before `npm test`).
    include: ["tests/**/*.test.ts"],
    environment: "node",
    // Tighten the default reporter so CI logs stay quiet on green.
    reporters: ["default"],
  },
});
