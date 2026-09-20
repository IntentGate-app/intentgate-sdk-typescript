/**
 * S4-WP-22 — THE DECISION THE SDK HANDS BACK.
 *
 * Until now this SDK had one shape for every answer: an exception. The module header on
 * errors.ts still says it — "Every gateway response that isn't a clean allow becomes an
 * exception" — and that is the defect this package closes.
 *
 * The readiness report put it in one sentence: **pure exceptions lose the distinction to a bare
 * `catch (e)`**. A DENY, a STEP_UP, an INDETERMINATE and an unreachable gateway are four
 * different facts, and a consumer that catches the base class has flattened them into one. The
 * flattening is invisible until the day someone needs to treat "the policy said no" differently
 * from "nobody answered" — and by then every call site has the same catch.
 *
 *   [FROZEN] ODR-R1-018 (TIER_1): "APPROVED — C + NO DEFAULT. Immutable value-returning
 *   Decision plus opt-in raise_for_permit(). NO ROUTE DEFAULT. UNAVAILABLE remains an OUTCOME,
 *   never another durable verdict."
 *
 * So: an obtained answer is a VALUE. An exception is reserved for the state in which NO ANSWER
 * EXISTS — transport failure, an unparseable body, a gateway that could not be reached. And
 * `raiseForPermit()` is there for the consumer who genuinely wants the throwing style, opt-in,
 * at their call site, with the verdict preserved in the exception they get.
 *
 * # THE FOUR VERDICTS AND THE ONE OUTCOME, WHICH ARE NOT THE SAME KIND OF THING
 *
 *   [FROZEN] ODR-R1-004 (TIER_1): "Durable verdicts are exactly PERMIT / DENY / STEP_UP /
 *   INDETERMINATE. ESCALATE -> INDETERMINATE. RESTRICT and REDACT are OBLIGATIONS, not
 *   verdicts."
 *
 * UNAVAILABLE is deliberately absent from the verdict list. It is an OUTCOME: a statement about
 * the exchange, not about the authority. Adding it as a fifth verdict would make "we could not
 * ask" indistinguishable in a switch statement from "we asked and no verdict could be reached",
 * and those have opposite remedies — one is retried, the other is not.
 */

import { GatewayError, IntentGateError } from "./errors.js";

/** The contract this SDK speaks. Matches `answer.CanonicalAnswerVersion` in the gateway. */
export const CANONICAL_ANSWER_VERSION = "IGA/1";

/** The header an SDK sends to ask for a contract version. */
export const NEGOTIATION_HEADER = "X-IntentGate-Answer-Contract";

export const VERDICTS = ["PERMIT", "DENY", "STEP_UP", "INDETERMINATE"] as const;
export type Verdict = (typeof VERDICTS)[number];

export const AUTHORITY_KINDS = ["UNBOUNDED", "BOUNDED"] as const;
export type AuthorityKind = (typeof AUTHORITY_KINDS)[number];

export const ASSERTION_CLASSES = ["CALLER_ASSERTED", "VERIFIED", "DERIVED"] as const;
export type AssertionClass = (typeof ASSERTION_CLASSES)[number];

export interface Reason {
  code: string;
  detail?: string;
}
export interface Bound {
  dimension: string;
  limit: string;
}
export interface Authority {
  kind: string;
  bounds?: Bound[];
}
export interface Validity {
  not_before: string;
  not_after: string;
  basis: string;
}
export interface Lineage {
  grant_id?: string;
  source_authority_id?: string;
  policy_revision?: string;
  evidence_ref?: string;
}
export interface Obligation {
  type: string;
  params?: Record<string, unknown>;
}
export interface Asserted {
  value: string;
  class: string;
}
export interface AbsentMaterial {
  name?: string;
  class: string;
  surface: string;
}

/** The wire shape, field for field and tag for tag with `answer.Answer`. */
export interface AnswerWire {
  contract_version?: string;
  verdict?: string;
  reason?: Reason;
  obligations?: Obligation[];
  authority?: Authority;
  validity?: Validity;
  decision_id?: string;
  lineage?: Lineage;
  subject?: Asserted;
  resource?: Asserted;
  absent?: AbsentMaterial[];
}

/**
 * THE REFUSAL VOCABULARY, one member per rule the gateway enforces, in the gateway's order.
 *
 * Named rather than free text so the shared conformance corpus can assert that this SDK refuses
 * the same case FOR THE SAME REASON as the Go contract and the platform mirror. Three
 * implementations that reject the same input for different reasons agree by coincidence.
 */
export const ANSWER_REFUSALS = [
  "UNKNOWN_CONTRACT_VERSION",
  "UNKNOWN_VERDICT",
  "MISSING_REASON",
  "MISSING_DECISION_ID",
  "BOUNDS_MISMATCH",
  "AUTHORITY_KIND",
  "MISSING_VALIDITY",
  "PERMIT_WITHOUT_LINEAGE",
  "ABSENCE_ON_A_DECISION",
  "ABSENT_MATERIAL_INCOMPLETE",
  "ABSENT_MATERIAL_LEAK",
  "ASSERTION_CLASS",
] as const;
export type AnswerRefusal = (typeof ANSWER_REFUSALS)[number];

const INPUT_PATH_MARKER = "input.";
const blank = (s: string | undefined): boolean => (s ?? "").trim() === "";

function lineageIsEmpty(l: Lineage): boolean {
  return blank(l.grant_id) && blank(l.source_authority_id) && blank(l.policy_revision) && blank(l.evidence_ref);
}

/**
 * Apply every rule the gateway applies, in its order, returning the FIRST refusal.
 *
 * First, because the gateway returns the first error — an SDK that reported a different one for
 * an input breaking two rules would disagree with the server about what was wrong, which is
 * worse than not checking at all.
 */
export function validateAnswer(a: AnswerWire): AnswerRefusal | null {
  if (a.contract_version !== CANONICAL_ANSWER_VERSION) return "UNKNOWN_CONTRACT_VERSION";
  if (!(VERDICTS as readonly string[]).includes(a.verdict ?? "")) return "UNKNOWN_VERDICT";
  if (blank(a.reason?.code)) return "MISSING_REASON";
  if (blank(a.decision_id)) return "MISSING_DECISION_ID";

  const kind = a.authority?.kind ?? "";
  const bounds = a.authority?.bounds ?? [];
  if (kind === "BOUNDED") {
    if (bounds.length === 0) return "BOUNDS_MISMATCH";
    for (const b of bounds) if (blank(b.dimension) || blank(b.limit)) return "BOUNDS_MISMATCH";
  } else if (kind === "UNBOUNDED") {
    if (bounds.length !== 0) return "BOUNDS_MISMATCH";
  } else {
    return "AUTHORITY_KIND";
  }

  if (blank(a.validity?.not_after) || blank(a.validity?.basis)) return "MISSING_VALIDITY";
  if (a.verdict === "PERMIT" && lineageIsEmpty(a.lineage ?? {})) return "PERMIT_WITHOUT_LINEAGE";

  const absent = a.absent ?? [];
  if (a.verdict !== "INDETERMINATE" && absent.length > 0) return "ABSENCE_ON_A_DECISION";
  for (const m of absent) {
    if (blank(m.class) || blank(m.surface)) return "ABSENT_MATERIAL_INCOMPLETE";
    if ((m.name ?? "").includes(INPUT_PATH_MARKER)) return "ABSENT_MATERIAL_LEAK";
  }

  for (const s of [a.subject, a.resource]) {
    if (!s) continue;
    if (!(ASSERTION_CLASSES as readonly string[]).includes(s.class)) return "ASSERTION_CLASS";
  }
  return null;
}

/** Raised when a consumer calls `raiseForPermit()` on a non-permit. Carries the Decision. */
export class NotPermittedError extends IntentGateError {
  readonly decision: Decision;
  constructor(decision: Decision) {
    super(`${decision.verdict}: ${decision.reason.code}`, { code: 0, data: decision.reason.detail });
    this.name = "NotPermittedError";
    this.decision = decision;
  }
}

/**
 * Raised when the gateway could not be asked, or answered something this SDK cannot read.
 *
 * An OUTCOME, not a verdict. It says nothing about the authority, only about the exchange.
 *
 *     [FROZEN] ODR-R1-018: "NO ROUTE DEFAULT. UNAVAILABLE remains an OUTCOME, never another
 *     durable verdict."
 *
 * ## WHY IT EXTENDS `GatewayError` RATHER THAN SITTING BESIDE IT
 *
 * Measured 2026-09-20: this class was exported and thrown NOWHERE, while `GatewayError` was
 * documented as "Network or transport failure reaching the gateway" — the same meaning. Two
 * classes for one outcome, and the throw went to the one the ruling does not name.
 *
 * Extending is what lets the ruled outcome be thrown without breaking a caller that catches the
 * older name. `catch (e) { if (e instanceof GatewayError) }` still catches an unavailable
 * exchange; `instanceof UnavailableError` now distinguishes "no answer exists" from "the gateway
 * answered and the answer was an error", which is the distinction the ruling preserves.
 */
export class UnavailableError extends GatewayError {
  constructor(message: string, opts?: { data?: unknown; cause?: unknown }) {
    super(message, { code: 0, ...(opts ?? {}) });
    this.name = "UnavailableError";
  }
}

/**
 * An immutable decision.
 *
 * Frozen at construction. A mutable Decision is a Decision a caller can edit before logging,
 * and the whole point of handing back a value rather than throwing is that the value is the
 * evidence.
 */
export class Decision {
  readonly contractVersion: string;
  readonly verdict: string;
  readonly reason: Reason;
  readonly obligations: readonly Obligation[];
  readonly authority: Authority;
  readonly validity: Validity;
  readonly decisionId: string;
  readonly lineage: Lineage;
  readonly subject?: Asserted;
  readonly resource?: Asserted;
  readonly absent: readonly AbsentMaterial[];

  /**
   * WHETHER THE SERVER HONOURED THE CONTRACT THIS SDK ASKED FOR.
   *
   *   [FROZEN] ODR-R1-053: "An unhonoured IGA/1 negotiation produces an EXPLICIT fallback,
   *   never a silent one."
   *
   * Today every legacy gateway route ignores `X-IntentGate-Answer-Contract` entirely — measured,
   * not assumed: `answer.Negotiate` has no callers outside its own package. So an SDK that asked
   * for IGA/1 and received the legacy shape cannot tell whether the server did not RECOGNISE the
   * version or does not IMPLEMENT negotiation, and the difference matters to whoever has to fix
   * it. This field says the request was not honoured; `downgradeReason` says what arrived
   * instead. A silent fallback would have been fewer lines and would have hidden the one fact a
   * consumer needs to act on.
   */
  readonly contractNegotiated: boolean;
  readonly downgradeReason?: string;

  private constructor(wire: AnswerWire, negotiated: boolean, downgradeReason?: string) {
    this.contractVersion = wire.contract_version ?? "";
    this.verdict = wire.verdict ?? "";
    this.reason = { code: wire.reason?.code ?? "", ...(wire.reason?.detail ? { detail: wire.reason.detail } : {}) };
    this.obligations = Object.freeze([...(wire.obligations ?? [])]);
    this.authority = { kind: wire.authority?.kind ?? "", ...(wire.authority?.bounds ? { bounds: [...wire.authority.bounds] } : {}) };
    this.validity = {
      not_before: wire.validity?.not_before ?? "",
      not_after: wire.validity?.not_after ?? "",
      basis: wire.validity?.basis ?? "",
    };
    this.decisionId = wire.decision_id ?? "";
    this.lineage = { ...(wire.lineage ?? {}) };
    if (wire.subject) this.subject = { ...wire.subject };
    if (wire.resource) this.resource = { ...wire.resource };
    this.absent = Object.freeze([...(wire.absent ?? [])]);
    this.contractNegotiated = negotiated;
    if (downgradeReason) this.downgradeReason = downgradeReason;
    Object.freeze(this);
  }

  /** Build from an IGA/1 answer the server honoured. */
  static fromAnswer(wire: AnswerWire): Decision {
    return new Decision(wire, true);
  }

  /**
   * Build from a shape that is NOT IGA/1, recording the downgrade on the decision itself.
   *
   * The verdict is whatever the legacy body said, and it is NOT translated into the four-verb
   * vocabulary here: a legacy `ALLOW` is not the same statement as an IGA/1 `PERMIT`, and
   * quietly renaming it would be the silent fallback the ruling forbids wearing a different
   * coat. `permits()` on a downgraded decision is therefore false, because the answer does not
   * validate — which is the honest reading of "we did not get the contract we asked for".
   */
  static fromDowngrade(wire: AnswerWire, reason: string): Decision {
    return new Decision(wire, false, reason);
  }

  /**
   * ONLY AN EXPLICIT, VALID PERMIT PERMITS.
   *
   * It validates rather than reading the verdict field, exactly as the gateway's `Permits()`
   * does. An answer that says PERMIT and breaks a rule — a permit resting on no lineage, say —
   * does not permit, and a consumer that read the field alone would act on it.
   */
  permits(): boolean {
    return this.refusal() === null && this.verdict === "PERMIT";
  }

  /** The rule this answer breaks, or null. Exposed so a consumer can log WHY it was not usable. */
  refusal(): AnswerRefusal | null {
    if (!this.contractNegotiated) return "UNKNOWN_CONTRACT_VERSION";
    return validateAnswer(this.toWire());
  }

  /**
   * Opt-in throwing style. ODR-R1-018's option C: the consumer who wants exceptions asks for
   * them, at their call site, and the Decision rides on the exception so nothing is lost.
   */
  raiseForPermit(): void {
    if (!this.permits()) throw new NotPermittedError(this);
  }

  /** The wire shape again, for logging and for the conformance corpus. */
  toWire(): AnswerWire {
    return {
      contract_version: this.contractVersion,
      verdict: this.verdict,
      reason: this.reason,
      ...(this.obligations.length > 0 ? { obligations: [...this.obligations] } : {}),
      authority: this.authority,
      validity: this.validity,
      decision_id: this.decisionId,
      lineage: this.lineage,
      ...(this.subject ? { subject: this.subject } : {}),
      ...(this.resource ? { resource: this.resource } : {}),
      ...(this.absent.length > 0 ? { absent: [...this.absent] } : {}),
    };
  }
}

/**
 * A batch result: one decision per entry, bound by the caller's own identifier.
 *
 * THERE IS NO AGGREGATE HELPER, AND ITS ABSENCE IS THE POINT.
 *
 * S4-WP-06's contract is explicit that an SDK convenience method like `allPermitted()` would
 * reintroduce the aggregate verdict on the client side and "must be explicitly forbidden in the
 * SDK acceptance, not merely omitted". So it is forbidden here, and a control scans this file's
 * source for the forbidden names rather than trusting that nobody adds one.
 *
 * A consumer that genuinely wants "did everything pass" writes the reduce themselves, at their
 * call site, where the decision to collapse four verdicts into a boolean is visible in their
 * own code review instead of hidden behind a helper this SDK blessed.
 */
export interface BatchDecision {
  entryId: string;
  decision: Decision;
}
