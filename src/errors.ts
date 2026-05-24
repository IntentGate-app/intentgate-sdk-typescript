/**
 * Exception hierarchy for the IntentGate SDK.
 *
 * Every gateway response that isn't a clean allow becomes a typed
 * Error. The hierarchy lets callers catch broadly (`catch (e) { if
 * (e instanceof IntentGateError) ... }`) or narrowly (`if (e instanceof
 * CapabilityError) ...`) depending on whether they want to distinguish
 * which check fired.
 *
 * Stage codes are stable across gateway versions:
 *
 *   CapabilityError     -32010
 *   IntentError         -32011
 *   PolicyError         -32012
 *   BudgetError         -32013
 *   ProvenanceError     -32014  (opt-in, AAI03 memory-poisoning defense)
 *
 * Anything else (parse errors, method not found, internal errors) is
 * a `ProtocolError`. Network and HTTP transport failures (timeouts,
 * connection refused, non-JSON responses) are `GatewayError` —
 * distinguish "the gateway is unreachable" from "the gateway said no".
 */

export class IntentGateError extends Error {
  /** JSON-RPC error code from the gateway, or 0 if client-side. */
  readonly code: number;

  /** Optional structured payload from the gateway's `error.data`. */
  readonly data: unknown;

  constructor(message: string, opts: { code?: number; data?: unknown; cause?: unknown } = {}) {
    super(message, { cause: opts.cause });
    // Each subclass overrides this in its own constructor; keep the
    // base default predictable for callers that introspect.
    this.name = "IntentGateError";
    this.code = opts.code ?? 0;
    this.data = opts.data;

    // Preserve the prototype chain across the down-leveled super()
    // call (the well-known TypeScript-when-targeting-ES5 footgun).
    // Targeting ES2022 makes this technically unnecessary, but the
    // explicit setPrototypeOf is a one-line insurance policy that
    // costs nothing and stops `instanceof` from breaking on older
    // bundlers that re-emit class syntax.
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Human-friendly string. When `data` is a string, it usually carries
   * the operator-facing reason (e.g. the Rego rule's explanation), so
   * we surface it on `toString`.
   */
  override toString(): string {
    if (typeof this.data === "string" && this.data.length > 0) {
      return `${this.message}: ${this.data}`;
    }
    return this.message;
  }
}

/** Network or transport failure reaching the gateway. */
export class GatewayError extends IntentGateError {
  constructor(message: string, opts?: { code?: number; data?: unknown; cause?: unknown }) {
    super(message, opts);
    this.name = "GatewayError";
  }
}

/** JSON-RPC error not in the four stage-specific codes. */
export class ProtocolError extends IntentGateError {
  constructor(message: string, opts?: { code?: number; data?: unknown; cause?: unknown }) {
    super(message, opts);
    this.name = "ProtocolError";
  }
}

/** Capability stage denied: token signature, expiry, agent lock, etc. */
export class CapabilityError extends IntentGateError {
  constructor(message: string, opts?: { code?: number; data?: unknown; cause?: unknown }) {
    super(message, opts);
    this.name = "CapabilityError";
  }
}

/** Intent stage denied: requested tool isn't in the extracted intent. */
export class IntentError extends IntentGateError {
  constructor(message: string, opts?: { code?: number; data?: unknown; cause?: unknown }) {
    super(message, opts);
    this.name = "IntentError";
  }
}

/** Policy stage denied: a Rego rule fired. */
export class PolicyError extends IntentGateError {
  constructor(message: string, opts?: { code?: number; data?: unknown; cause?: unknown }) {
    super(message, opts);
    this.name = "PolicyError";
  }
}

/** Budget stage denied: max-calls caveat exhausted. */
export class BudgetError extends IntentGateError {
  constructor(message: string, opts?: { code?: number; data?: unknown; cause?: unknown }) {
    super(message, opts);
    this.name = "BudgetError";
  }
}

/**
 * Provenance stage denied: the opt-in AAI03 memory-poisoning defense
 * rejected the call. Raised when the X-Intent-Memory-Provenance header
 * carries an entry whose HMAC does not verify, whose prev_hash chain
 * is broken, or whose envelope is structurally malformed.
 *
 * JSON-RPC code -32014. Only emitted by gateways with provenance
 * enabled (INTENTGATE_PROVENANCE_ENABLED=true); not raised against
 * the default four-check pipeline.
 */
export class ProvenanceError extends IntentGateError {
  constructor(message: string, opts?: { code?: number; data?: unknown; cause?: unknown }) {
    super(message, opts);
    this.name = "ProvenanceError";
  }
}

const CODE_TO_CLASS: Record<number, typeof IntentGateError> = {
  [-32010]: CapabilityError,
  [-32011]: IntentError,
  [-32012]: PolicyError,
  [-32013]: BudgetError,
  [-32014]: ProvenanceError,
};

/**
 * Pick the typed exception class for a JSON-RPC error code. Codes in
 * the stage range produce the matching stage class; anything else
 * (parse, invalid request, method not found, internal error,
 * out-of-range custom codes) maps to ProtocolError.
 */
export function forCode(code: number): typeof IntentGateError {
  return CODE_TO_CLASS[code] ?? ProtocolError;
}
