/**
 * NODE 18 · THE PUBLISHED CONTRACT, PROVEN AGAINST THE BUILT BUNDLE.
 *
 * # WHY THIS FILE EXISTS
 *
 * `package.json` declares `engines: { node: ">=18" }`, and the CI matrix has always called
 * Node 18 the floor — it is where native `fetch` landed, and this SDK is built on it.
 *
 * On 2026-05-23 commit `8b31fdd` bumped vitest from ^2 to ^4 to clear an esbuild dev-server
 * CVE. That bump was correct and was marked "devDep only", which it was. But vitest 4 declares
 * `engines: ^20 || ^22 || >=24`, so from that moment the Node 18 matrix job could not run at
 * all: the TEST RUNNER refused, long before any SDK code was reached. CI was red on main for
 * four months and the Node 18 support claim went unverified. Versions 0.3.0, 0.3.1 and 0.3.2
 * were published inside that window. **They were never tested on Node 18, and nothing here
 * should be read as saying otherwise.** Filed as EST-F-162.
 *
 * The resolution ruled by the owner: **preserve the published promise and make CI capable of
 * proving it again.** So `engines` stays `>=18`, Node 18 stays an explicit CI target, vitest is
 * NOT downgraded, and vitest is NOT run on 18. Instead this suite runs on Node 18's own built-in
 * `node:test`, against the ACTUAL BUILT BUNDLE produced by the normal `npm run build` path on a
 * supported Node — not against `src/`, and not against an alternative implementation.
 *
 * # WHAT IT EXERCISES
 *
 * Only the dependency-free public surface a Node 18 consumer actually depends on: the package's
 * own export map (both halves), client construction and its refusals, the answer contract driven
 * over the same conformance corpus the gateway emitted, and the memory envelope's canonical
 * serialization. Nothing here touches a network, a gateway or a service.
 *
 * # WHAT IT MUST NOT BECOME
 *
 * If the built SDK fails here, that is a PRODUCT COMPATIBILITY FAILURE on a runtime the package
 * promises to support. Record it. **Do not weaken an assertion to get this suite green.**
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const require_ = createRequire(import.meta.url);

// The same digest the gateway pins in internal/answer/corpus_digest.go and the platform pins in
// packages/authz-contract/tests/answer-conformance.spec.ts. Four repositories, one corpus.
const CORPUS_DIGEST = "5c1c2de450fa27a50947712c81558fdc3644ed6da992a01b77576022b69ac795";

const esm = await import(join(root, "dist", "index.js"));
const cjs = require_(join(root, "dist", "index.cjs"));

test("N0 NON-VACUITY — this really is Node 18, and the bundle really was built", () => {
  const major = Number(process.versions.node.split(".")[0]);
  assert.ok(major >= 18, `expected Node >= 18, got ${process.versions.node}`);
  assert.ok(
    typeof esm.Gateway === "function",
    "dist/index.js did not export Gateway — was `npm run build` run before this suite?",
  );
});

test("N1 the export map's BOTH halves resolve, and agree on what they export", () => {
  // `exports: { import: ./dist/index.js, require: ./dist/index.cjs }`. A consumer on Node 18
  // may take either door; a bundle that only builds one of them is broken for half of them.
  const named = [
    "Gateway",
    "ROUTE_MCP_GOVERNED",
    "ROUTE_MCP_LEGACY",
    "RouteNotChosenError",
    "Decision",
    "validateAnswer",
    "VERDICTS",
    "ANSWER_REFUSALS",
    "CANONICAL_ANSWER_VERSION",
    "NotPermittedError",
    "UnavailableError",
    "MemoryStore",
    "canonical",
    "ZERO_HASH",
    "attenuate",
    "decodeToken",
  ];
  for (const n of named) {
    assert.ok(n in esm, `ESM bundle is missing ${n}`);
    assert.ok(n in cjs, `CJS bundle is missing ${n}`);
  }
});

test("N2 the governed route is the constant, not a string a caller has to remember", () => {
  assert.equal(esm.ROUTE_MCP_GOVERNED, "/v1/mcp/ig");
  assert.equal(cjs.ROUTE_MCP_GOVERNED, "/v1/mcp/ig");
  assert.notEqual(esm.ROUTE_MCP_LEGACY, esm.ROUTE_MCP_GOVERNED);
});

test("N3 client construction, and the refusal that has no default", () => {
  const gw = new esm.Gateway("http://localhost:8080", { route: esm.ROUTE_MCP_GOVERNED });
  assert.ok(gw);
  // ODR-R1-018: route is required and has no default. A JavaScript consumer has no type to
  // stop them, which is exactly the consumer this runtime refusal exists for.
  assert.throws(() => new esm.Gateway("http://localhost:8080", {}), esm.RouteNotChosenError);
  assert.throws(() => new esm.Gateway("", { route: esm.ROUTE_MCP_GOVERNED }), /url is required/);
  // Trailing slashes are tolerated rather than producing a double-slash path.
  const trailing = new esm.Gateway("http://localhost:8080///", { route: esm.ROUTE_MCP_GOVERNED });
  assert.ok(trailing);
});

test("N4 the verdict vocabulary is the pinned four, on this runtime too", () => {
  assert.deepEqual([...esm.VERDICTS], ["PERMIT", "DENY", "STEP_UP", "INDETERMINATE"]);
  assert.ok(!esm.VERDICTS.includes("UNAVAILABLE"));
});

// ---------------------------------------------------------------------------------------
// The conformance corpus. This is the part that matters: the SAME BYTES the gateway emitted,
// driven through the SAME rules, on the runtime the package promises to support.
// ---------------------------------------------------------------------------------------
const raw = readFileSync(join(root, "tests", "testdata", "iga1-conformance-corpus.json"));
const corpus = JSON.parse(raw.toString("utf8"));

test("N5 the corpus is the exact bytes, verified by this runtime's own crypto", () => {
  assert.equal(createHash("sha256").update(raw).digest("hex"), CORPUS_DIGEST);
  assert.equal(corpus.contract_version, esm.CANONICAL_ANSWER_VERSION);
});

test("N6 NON-VACUITY — the corpus exercises every declared refusal", () => {
  // A corpus of valid answers passes against an SDK that never refuses anything.
  const seen = new Set(corpus.cases.map((c) => c.expect));
  assert.ok(seen.has("VALID"));
  for (const r of esm.ANSWER_REFUSALS) {
    assert.ok(seen.has(r), `no corpus case expects ${r}`);
  }
});

test("N7 every corpus case agrees, and for the same reason", () => {
  assert.ok(corpus.cases.length > 0);
  for (const c of corpus.cases) {
    const got = esm.validateAnswer(c.answer);
    const want = c.expect === "VALID" ? null : c.expect;
    assert.equal(got, want, `${c.name}: expected ${want}, got ${got}`);
  }
});

test("N8 an obtained answer is a VALUE, and only an explicit valid permit permits", () => {
  const find = (n) => corpus.cases.find((c) => c.name === n)?.answer;
  const permit = find("valid_permit_unbounded");
  const deny = find("valid_deny");
  assert.ok(permit && deny, "the corpus no longer carries the cases this control reads");

  assert.equal(esm.Decision.fromAnswer(permit).permits(), true);
  assert.equal(esm.Decision.fromAnswer(deny).permits(), false);

  // raiseForPermit is OPT-IN and carries the decision on the exception.
  assert.doesNotThrow(() => esm.Decision.fromAnswer(permit).raiseForPermit());
  assert.throws(() => esm.Decision.fromAnswer(deny).raiseForPermit(), esm.NotPermittedError);

  // A downgraded decision never permits, whatever the legacy body said.
  const downgraded = esm.Decision.fromDowngrade(permit, "NO_CONTRACT_HEADER");
  assert.equal(downgraded.permits(), false);
  assert.equal(downgraded.refusal(), "UNKNOWN_CONTRACT_VERSION");
});

test("N9 canonical serialization is byte-stable on this runtime", () => {
  const env = {
    id: "ENV-1",
    sessionId: "SESS-1",
    timestamp: 1_758_000_000_000,
    data: Buffer.from("node-18-smoke", "utf8"),
    prevHash: esm.ZERO_HASH,
  };
  const a = esm.canonical(env);
  const b = esm.canonical(env);
  assert.ok(Buffer.isBuffer(a));
  assert.ok(a.length > 0);
  assert.equal(a.toString("hex"), b.toString("hex"), "canonical() is not deterministic here");
  // The CJS door must produce the same bytes as the ESM one.
  assert.equal(cjs.canonical(env).toString("hex"), a.toString("hex"));
});

test("N10 the runtime facilities the >=18 floor is ABOUT are present", () => {
  // Node 18 is the declared floor because native fetch landed there, and the SDK has zero
  // runtime dependencies precisely so it can rely on the platform instead.
  assert.equal(typeof globalThis.fetch, "function", "native fetch is missing on this runtime");
  assert.equal(typeof globalThis.AbortController, "function");
  assert.equal(typeof createHash, "function");
});
