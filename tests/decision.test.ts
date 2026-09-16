import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ANSWER_REFUSALS,
  CANONICAL_ANSWER_VERSION,
  Decision,
  NotPermittedError,
  VERDICTS,
  validateAnswer,
  type AnswerRefusal,
  type AnswerWire,
} from "../src/decision.js";
import { IntentGateError } from "../src/errors.js";

/**
 * S4-WP-22 :: THE SDK SPEAKS THE SAME CONTRACT AS THE GATEWAY, PROVEN AGAINST THE SAME BYTES.
 *
 * The corpus is emitted by `gateway/internal/answer`'s own test and carried into this repository
 * verbatim. The platform mirror replays it too. Three runtimes, one artifact, one digest — and
 * each case names the REFUSAL, because three implementations that reject the same input for
 * different reasons agree by coincidence.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS_PATH = join(HERE, "testdata", "iga1-conformance-corpus.json");
const raw = readFileSync(CORPUS_PATH);

/** sha256 of the corpus. The gateway pins it in answer.CorpusDigest; the platform pins it too. */
const CORPUS_DIGEST = "5c1c2de450fa27a50947712c81558fdc3644ed6da992a01b77576022b69ac795";

interface CorpusCase {
  name: string;
  answer: AnswerWire;
  expect: AnswerRefusal | "VALID";
}
const corpus = JSON.parse(raw.toString("utf8")) as { artifact: string; contract_version: string; cases: CorpusCase[] };

describe("the corpus is the one every runtime reads", () => {
  it("is the exact bytes the gateway emitted", () => {
    expect(createHash("sha256").update(raw).digest("hex")).toBe(CORPUS_DIGEST);
  });

  it("declares the contract it is about", () => {
    expect(corpus.artifact).toBe("intentgate-iga1-conformance-corpus");
    expect(corpus.contract_version).toBe(CANONICAL_ANSWER_VERSION);
  });

  it("exercises every refusal, so no rule is untested in this runtime either", () => {
    // Non-vacuity. A corpus of valid answers passes against an SDK that never refuses anything.
    const seen = new Set(corpus.cases.map((c) => c.expect));
    expect(seen.has("VALID")).toBe(true);
    for (const r of ANSWER_REFUSALS) expect(seen.has(r)).toBe(true);
  });
});

describe("every case agrees with the gateway, and for the same reason", () => {
  for (const c of corpus.cases) {
    it(c.name, () => {
      expect(validateAnswer(c.answer)).toBe(c.expect === "VALID" ? null : c.expect);
    });
  }
});

describe("S4-WP-22 :: an obtained answer is a VALUE, not an exception", () => {
  const permit = corpus.cases.find((c) => c.name === "valid_permit_unbounded")!.answer;
  const deny = corpus.cases.find((c) => c.name === "valid_deny")!.answer;
  const stepUp = corpus.cases.find((c) => c.name === "valid_step_up")!.answer;
  const indet = corpus.cases.find((c) => c.name === "valid_indeterminate_without_absent")!.answer;

  it("returns a decision for every verdict, including the ones that are not permits", () => {
    // The defect this closes: with exceptions only, a DENY, a STEP_UP and an INDETERMINATE all
    // arrive at the same `catch (e)` and the caller has flattened three different facts into
    // one.
    for (const [wire, verdict] of [
      [permit, "PERMIT"],
      [deny, "DENY"],
      [stepUp, "STEP_UP"],
      [indet, "INDETERMINATE"],
    ] as const) {
      const d = Decision.fromAnswer(wire);
      expect(d.verdict).toBe(verdict);
      expect(d.decisionId.length).toBeGreaterThan(0);
    }
  });

  it("only an explicit, valid permit permits", () => {
    expect(Decision.fromAnswer(permit).permits()).toBe(true);
    expect(Decision.fromAnswer(deny).permits()).toBe(false);
    expect(Decision.fromAnswer(stepUp).permits()).toBe(false);
    expect(Decision.fromAnswer(indet).permits()).toBe(false);

    // permits() VALIDATES rather than reading the field. An answer that says PERMIT and rests
    // on no lineage does not permit, and a consumer reading the field alone would act on it.
    const bad = corpus.cases.find((c) => c.name === "permit_without_lineage")!.answer;
    const d = Decision.fromAnswer(bad);
    expect(d.verdict).toBe("PERMIT");
    expect(d.permits()).toBe(false);
    expect(d.refusal()).toBe("PERMIT_WITHOUT_LINEAGE");
  });

  it("is immutable, because the value IS the evidence", () => {
    const d = Decision.fromAnswer(permit);
    expect(Object.isFrozen(d)).toBe(true);
    expect(() => {
      (d as unknown as { verdict: string }).verdict = "PERMIT";
    }).toThrow();
  });

  it("raiseForPermit is OPT-IN and carries the decision on the exception", () => {
    expect(() => Decision.fromAnswer(permit).raiseForPermit()).not.toThrow();
    const d = Decision.fromAnswer(deny);
    try {
      d.raiseForPermit();
      throw new Error("expected a throw");
    } catch (e) {
      // ODR-R1-018 option C: the consumer who wants exceptions asks for them at their call
      // site, and nothing is lost when they do.
      expect(e).toBeInstanceOf(NotPermittedError);
      expect(e).toBeInstanceOf(IntentGateError);
      expect((e as NotPermittedError).decision.verdict).toBe("DENY");
      expect((e as NotPermittedError).decision.reason.code).toBe("NO_GRANT");
    }
  });
});

describe("S4-WP-22 :: UNAVAILABLE is an outcome, never a fifth verdict", () => {
  it("the verdict vocabulary has exactly four members and UNAVAILABLE is not one", () => {
    //   [FROZEN] ODR-R1-018: "UNAVAILABLE remains an OUTCOME, never another durable verdict."
    //
    // A fifth verdict would make "we could not ask" indistinguishable in a switch from "we
    // asked and no verdict could be reached", and those have opposite remedies: one is retried,
    // the other is not.
    expect([...VERDICTS]).toEqual(["PERMIT", "DENY", "STEP_UP", "INDETERMINATE"]);
    expect((VERDICTS as readonly string[]).includes("UNAVAILABLE")).toBe(false);
  });
});

describe("S4-WP-22 :: an unhonoured negotiation is explicit, never silent", () => {
  it("records the downgrade on the decision itself", () => {
    //   [FROZEN] ODR-R1-053: "An unhonoured IGA/1 negotiation produces an EXPLICIT fallback,
    //   never a silent one."
    //
    // Every legacy gateway route ignores the negotiation header today — measured, not assumed.
    // So an SDK that asked for IGA/1 and got the legacy shape cannot tell whether the server
    // did not RECOGNISE the version or does not IMPLEMENT negotiation, and whoever has to fix
    // it needs that distinction.
    const legacy = { decision: "ALLOW", record: { decision_id: "DEC-1" } } as unknown as AnswerWire;
    const d = Decision.fromDowngrade(legacy, "server returned the legacy {decision, record} shape");
    expect(d.contractNegotiated).toBe(false);
    expect(d.downgradeReason).toContain("legacy");
  });

  it("a downgraded decision never permits, whatever the legacy body said", () => {
    // A legacy ALLOW is not the same statement as an IGA/1 PERMIT, and renaming it would be
    // the silent fallback in a different coat.
    const legacy = { verdict: "ALLOW", decision_id: "DEC-1" } as unknown as AnswerWire;
    const d = Decision.fromDowngrade(legacy, "legacy shape");
    expect(d.permits()).toBe(false);
    expect(d.refusal()).toBe("UNKNOWN_CONTRACT_VERSION");
  });
});

describe("S4-WP-22 :: there is no aggregate helper, and its absence is asserted", () => {
  const src = readFileSync(join(HERE, "..", "src", "decision.ts"), "utf8");
  // Comments stripped first: this file's own prose names the forbidden helpers, and a scan that
  // reads prose finds the very word it is looking for.
  const code = src.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");

  it("reads real source", () => {
    // Non-vacuity: a scan that read nothing reports no findings and looks identical to a scan
    // that read everything and found none.
    expect(code).toContain("export class Decision");
    expect(code.length).toBeGreaterThan(1000);
  });

  it("declares no allPermitted, anyDenied or worstVerdict", () => {
    // S4-WP-06's contract: such a helper "would reintroduce the aggregate verdict on the client
    // side and must be explicitly forbidden in the SDK acceptance, not merely omitted".
    for (const forbidden of ["allPermitted", "anyDenied", "worstVerdict", "permitCount", "summary"]) {
      expect(code).not.toContain(forbidden);
    }
  });
});

describe("S4-WP-22 :: the route has no default, and a wrong route is not a denial", () => {
  it("refuses to construct a Gateway that did not choose a route", async () => {
    //   [FROZEN] ODR-R1-018: "NO ROUTE DEFAULT."
    //
    // /v1/mcp runs the legacy capability/bundle pipeline; /v1/mcp/ig is governed solely by the
    // BA-/IG- chain. They are different authorities. A default would move every consumer from
    // one to the other on an upgrade and none of them would read a changelog entry about it.
    const { Gateway, RouteNotChosenError, ROUTE_MCP_GOVERNED, ROUTE_MCP_LEGACY } = await import(
      "../src/client.js"
    );

    // The runtime check exists for the JavaScript consumer who has no type to stop them, which
    // is exactly the consumer this refusal is for.
    expect(() => new (Gateway as unknown as new (u: string, o?: unknown) => unknown)("http://gw.example")).toThrow(
      RouteNotChosenError,
    );
    expect(
      () => new (Gateway as unknown as new (u: string, o?: unknown) => unknown)("http://gw.example", { route: "  " }),
    ).toThrow(RouteNotChosenError);

    // The message names both routes, because an error that says "required" and stops there
    // sends the reader to the source to find out what the options were.
    try {
      new (Gateway as unknown as new (u: string, o?: unknown) => unknown)("http://gw.example");
    } catch (e) {
      expect((e as Error).message).toContain(ROUTE_MCP_GOVERNED);
      expect((e as Error).message).toContain(ROUTE_MCP_LEGACY);
    }
  });

  it("sends to the chosen route and reports a missing one as configuration, not denial", async () => {
    const { Gateway, ROUTE_MCP_GOVERNED, RouteNotFoundError } = await import("../src/client.js");
    const { PolicyError } = await import("../src/errors.js");

    let seen = "";
    const fake = (async (url: string) => {
      seen = url;
      return new Response("no such route", { status: 404 });
    }) as unknown as typeof fetch;

    const gw = new Gateway("http://gw.example", { route: ROUTE_MCP_GOVERNED, fetch: fake });
    await expect(gw.toolCall("read_invoice")).rejects.toBeInstanceOf(RouteNotFoundError);
    expect(seen).toBe(`http://gw.example${ROUTE_MCP_GOVERNED}`);

    // The failure this prevents: an operator reading "HTTP 404" beside a run of blocked calls
    // and concluding the gateway is refusing them. Only one of these is fixed by editing
    // config, and the SDK must not make them look alike.
    await expect(gw.toolCall("read_invoice")).rejects.not.toBeInstanceOf(PolicyError);
  });
});

describe("S4-WP-22 :: the indeterminate stimulus, produced deliberately", () => {
  it("is a fixture, because no route has ever emitted one", async () => {
    //   [FROZEN] ODR-R1-053: "The indeterminate stimulus is produced deliberately, since no
    //   route has ever emitted one." (S4-WP-22-D3, option A)
    //
    // wellformed.Enumeration.Indeterminate() has zero callers outside its package. So this
    // proves the SDK's HANDLING of an INDETERMINATE and nothing about the gateway's ability to
    // produce one — and saying which of the two was proven is the whole reason the ruling
    // chose a fixture over a staged Lab stimulus.
    const wire = corpus.cases.find((c) => c.name === "valid_indeterminate_with_absent")!.answer;
    const d = Decision.fromAnswer(wire);

    expect(d.verdict).toBe("INDETERMINATE");
    expect(d.permits()).toBe(false);
    expect(d.refusal()).toBeNull(); // a VALID answer that simply is not a permit
    expect(d.absent).toHaveLength(1);
    expect(d.absent[0]!.surface).toBe("authorize");

    // And the distinction the package exists for: an INDETERMINATE is an ANSWER. It is not the
    // same as no answer, which is what UnavailableError means.
    expect(() => d.raiseForPermit()).toThrow(NotPermittedError);
  });
});
