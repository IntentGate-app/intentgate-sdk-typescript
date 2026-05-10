/**
 * Pure-TypeScript capability-token helpers.
 *
 * The IntentGate gateway issues capability tokens with a Macaroons-
 * style chained-HMAC signature: a token holder can derive a strictly
 * more restrictive child token by appending a caveat and HMAC'ing it
 * under the parent's signature **without ever touching the master
 * key**. That is the defining property of capability tokens, and the
 * reason this module ships in the SDK.
 *
 * Use case. A parent agent receives a token allowing tools `[a, b,
 * c]`, spawns a sub-agent for one task, and wants the sub-agent's
 * token to allow only `[a]`. The parent calls {@link attenuate} and
 * hands the resulting token string to the sub-agent. The gateway
 * (which has the master key) accepts the attenuated token and rejects
 * any sub-agent call that would have needed `b` or `c`.
 *
 * What we don't do here:
 *
 * - **No master key access.** By design — that's what makes
 *   attenuation safe. To mint a brand-new root token, use the
 *   gateway's `POST /v1/admin/mint` endpoint, not this module.
 * - **No semantic narrowing check.** Adding a "broader" caveat
 *   doesn't widen the chain because the parent's narrower caveat
 *   fires first on the gateway side. We don't second-guess the
 *   caller; policy belongs in the gateway, not the SDK.
 *
 * # Wire format
 *
 * We mirror the Go gateway's serialization byte-for-byte on the one
 * place it matters: the new caveat's canonical JSON, which seeds the
 * HMAC step. Anywhere else, JSON ordering doesn't affect correctness
 * because the gateway re-marshals from its parsed Go struct during
 * `Verify`. Every implementation in this package matches the Python
 * SDK byte-for-byte against the same fixtures, so a token attenuated
 * by either SDK verifies on the same gateway.
 */

import { createHmac } from "node:crypto";

/**
 * Caveat-type identifiers, kept in sync with the Go consts in
 * gateway/internal/capability/token.go.
 */
export const CaveatType = {
  EXPIRY: "exp",
  TOOL_ALLOW: "tool_allow",
  TOOL_DENY: "tool_deny",
  AGENT_LOCK: "agent_lock",
  MAX_CALLS: "max_calls",
} as const;

/**
 * A structured restriction recorded in a token's chain. Only fields
 * relevant to the {@link type} are emitted; the rest are omitted from
 * the JSON output (matching Go's `omitempty` tags).
 *
 * Field order on the wire: `t, tools, agent, exp, max_calls`. This
 * matches Go's encoding/json declaration-order behavior and seeds
 * the HMAC step that derives the child's signature.
 */
export interface Caveat {
  type: string;
  tools?: string[];
  agent?: string;
  /** Unix seconds. */
  expiry?: number;
  maxCalls?: number;
}

export class AttenuationError extends Error {
  constructor(message: string, opts?: { cause?: unknown }) {
    super(message, { cause: opts?.cause });
    this.name = "AttenuationError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---- base64url ---------------------------------------------------

/** Decode an unpadded RawURLEncoding (RFC 4648 §5) base64url string. */
function b64urlDecode(s: string): Uint8Array {
  // Restore standard alphabet + padding for atob/Buffer.
  const standard = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = standard.length % 4 === 0 ? "" : "=".repeat(4 - (standard.length % 4));
  try {
    return new Uint8Array(Buffer.from(standard + pad, "base64"));
  } catch (cause) {
    throw new AttenuationError(`invalid base64url: ${stringifyCause(cause)}`, { cause });
  }
}

/** Encode bytes as unpadded RawURLEncoding base64url. */
function b64urlEncode(b: Uint8Array): string {
  return Buffer.from(b)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

// ---- canonical caveat bytes -------------------------------------

/**
 * The exact byte sequence Go's `encoding/json` produces for a Caveat.
 *
 * **CRITICAL**: this is the input to the HMAC step that derives the
 * child's signature. Mismatch here = gateway rejects the child.
 *
 * Constraints, all matched by Go, Python SDK, and this implementation:
 *
 * - Field order: `t, tools, agent, exp, max_calls`.
 * - No whitespace between separators (`{"t":"x","tools":["a"]}`).
 * - Empty/zero fields omitted (Go's `json:",omitempty"`).
 * - ASCII output: only forbidden characters are escaped, not
 *   "interesting" ASCII like `<`. Both Go and Node behave this way
 *   by default, and the fixture tests assert byte equality across
 *   all three implementations.
 *
 * The implementation builds a fresh object with keys inserted in
 * canonical order; ECMA-262 specifies that JSON.stringify on a plain
 * object iterates own string keys in insertion order, so this is
 * deterministic.
 */
function canonicalCaveatBytes(c: Caveat): Uint8Array {
  // Build the on-the-wire object in field order. Skip empty/zero
  // values to match Go's `omitempty`.
  const obj: Record<string, unknown> = {};
  // `t` has no omitempty in Go: always present, even if empty.
  obj["t"] = c.type;
  if (c.tools && c.tools.length > 0) {
    obj["tools"] = [...c.tools];
  }
  if (c.agent) {
    obj["agent"] = c.agent;
  }
  if (c.expiry) {
    obj["exp"] = Math.trunc(c.expiry);
  }
  if (c.maxCalls) {
    obj["max_calls"] = Math.trunc(c.maxCalls);
  }
  // JSON.stringify with no indent argument produces no whitespace —
  // this is the equivalent of Python's `separators=(',', ':')` and
  // matches Go's default Marshal output.
  const json = JSON.stringify(obj);
  return new TextEncoder().encode(json);
}

// ---- decode / attenuate -----------------------------------------

/**
 * Decode a base64url(JSON) token into its parsed object. No signature
 * check (the gateway does that). Useful for inspecting the chain —
 * `decodeToken(t).cav` lists the caveats bound to the token.
 */
export function decodeToken(token: string): Record<string, unknown> {
  const raw = b64urlDecode(token);
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch (cause) {
    throw new AttenuationError(`token JSON is malformed: ${stringifyCause(cause)}`, {
      cause,
    });
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new AttenuationError("token JSON is not an object");
  }
  return parsed as Record<string, unknown>;
}

export interface AttenuateOptions {
  /** Narrow to this tool whitelist (caveat type `tool_allow`). */
  addTools?: string[];

  /** Add a deny list (caveat type `tool_deny`). Additive on top of any parent deny. */
  denyTools?: string[];

  /** Cap remaining calls (caveat type `max_calls`). The chain enforces the minimum. */
  maxCalls?: number;

  /** Set absolute expiry (Unix seconds). Caveat type `exp`. */
  expiresAt?: number;

  /** Convenience: now + N seconds. Caveat type `exp`. */
  expiresInSeconds?: number;

  /** User-supplied caveats appended last (advanced). */
  extra?: Caveat[];
}

/**
 * Append narrowing caveats to a parent token and return a new token
 * string that the gateway accepts as a cryptographic descendant of
 * the parent.
 *
 * Each option groups one common attenuation pattern. Multiple options
 * combine; each generates one caveat in this order:
 *
 *   1. `addTools`         → `tool_allow` caveat
 *   2. `denyTools`        → `tool_deny` caveat
 *   3. `maxCalls`         → `max_calls` caveat
 *   4. `expiresAt` /      → `exp` caveat (absolute Unix seconds)
 *      `expiresInSeconds`
 *   5. `extra`            → user-supplied caveats appended last
 *
 * @example
 * ```ts
 * import { attenuate } from "@netgnarus/intentgate";
 *
 * // Parent token: agent allowed [search, read, email] for 1h.
 * // Child: only [search, read], one call max.
 * const child = attenuate(parentToken, {
 *   addTools: ["search", "read"],
 *   maxCalls: 1,
 * });
 *
 * // Hand `child` to the sub-agent.
 * ```
 */
export function attenuate(token: string, opts: AttenuateOptions = {}): string {
  const parsed = decodeToken(token);

  if (typeof parsed["sig"] !== "string") {
    throw new AttenuationError("token is missing 'sig' field");
  }
  if (!Array.isArray(parsed["cav"])) {
    throw new AttenuationError("token is missing 'cav' field");
  }
  if (typeof parsed["root_jti"] !== "string" || parsed["root_jti"] === "") {
    throw new AttenuationError(
      "token has no root_jti (was it minted by gateway < v0.7?)",
    );
  }
  if (typeof parsed["tenant"] !== "string" || parsed["tenant"] === "") {
    throw new AttenuationError(
      "token has no tenant (was it minted by gateway < v0.9?)",
    );
  }

  // Tenant is signed in the chain seed by the gateway and propagates
  // through every HMAC step unchanged — attenuation cannot pivot
  // tenants. We don't re-validate that here because the cryptographic
  // chain enforces it; the explicit check above just gives a friendly
  // error for v0.8 tokens that pre-date the tenant claim.

  const cavs: Record<string, unknown>[] = [...(parsed["cav"] as Record<string, unknown>[])];
  let sig = b64urlDecode(parsed["sig"]);

  const newCaveats: Caveat[] = [];
  if (opts.addTools && opts.addTools.length > 0) {
    newCaveats.push({ type: CaveatType.TOOL_ALLOW, tools: [...opts.addTools] });
  }
  if (opts.denyTools && opts.denyTools.length > 0) {
    newCaveats.push({ type: CaveatType.TOOL_DENY, tools: [...opts.denyTools] });
  }
  if (opts.maxCalls !== undefined) {
    if (opts.maxCalls < 0) {
      throw new AttenuationError("maxCalls must be >= 0");
    }
    newCaveats.push({ type: CaveatType.MAX_CALLS, maxCalls: Math.trunc(opts.maxCalls) });
  }
  if (opts.expiresAt !== undefined || opts.expiresInSeconds !== undefined) {
    const exp =
      opts.expiresAt ?? Math.floor(Date.now() / 1000) + (opts.expiresInSeconds ?? 0);
    newCaveats.push({ type: CaveatType.EXPIRY, expiry: Math.trunc(exp) });
  }
  if (opts.extra && opts.extra.length > 0) {
    newCaveats.push(...opts.extra);
  }

  if (newCaveats.length === 0) {
    throw new AttenuationError(
      "attenuate() requires at least one narrowing argument " +
        "(addTools, denyTools, maxCalls, expiresInSeconds, expiresAt, or extra)",
    );
  }

  // Walk the new caveats forward, hopping the HMAC chain one step
  // per caveat. The Go gateway re-walks the same chain in `Verify`.
  for (const c of newCaveats) {
    const cb = canonicalCaveatBytes(c);
    sig = new Uint8Array(createHmac("sha256", sig).update(cb).digest());
    // Append the same on-the-wire object to the cav array. Use
    // canonicalCaveatBytes' object-build logic to stay consistent
    // with what we just HMAC'd.
    cavs.push(JSON.parse(new TextDecoder().decode(cb)) as Record<string, unknown>);
  }

  // Re-encode. Go decodes JSON order-independently during Verify, so
  // any field ordering on the outer envelope is fine — separators
  // only matter for the per-caveat canonical bytes inside the HMAC.
  const child: Record<string, unknown> = { ...parsed };
  child["cav"] = cavs;
  child["sig"] = b64urlEncode(sig);
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(child)));
}

function stringifyCause(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  return String(cause);
}
