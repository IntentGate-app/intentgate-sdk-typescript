/**
 * Tests for the pure-TypeScript capability helpers.
 *
 * Wire-format compatibility is the central concern: bytes the TS SDK
 * HMACs MUST match what the Go gateway re-marshals during Verify.
 * Two strategies cover that:
 *
 *   1. Direct byte comparison against canonical samples — the same
 *      fixtures the Python SDK asserts against. If both SDKs
 *      produce the exact bytes the Go gateway expects, all three
 *      stay interoperable.
 *   2. End-to-end round-trip simulation: build a parent token whose
 *      signature is a known HMAC chain, attenuate it in TS, then
 *      independently recompute the chain (mimicking what the Go
 *      gateway does) and confirm the new signature matches.
 */

import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  AttenuationError,
  type Caveat,
  CaveatType,
  attenuate,
  decodeToken,
} from "../src/capability.js";

// --- Internal helpers (mirror the Python tests) -----------------------

/**
 * Re-implementation of the SDK's canonicalCaveatBytes so the tests
 * can both:
 *   - assert known-bytes equality against fixed strings (locks the
 *     wire format)
 *   - reconstruct expected HMACs without reaching into private SDK
 *     internals
 *
 * Keep this byte-for-byte identical to src/capability.ts. The
 * presence of this duplicate is intentional: a test that only
 * compared internal output to itself would never catch a regression.
 */
function canonicalCaveatBytes(c: Caveat): Uint8Array {
  const obj: Record<string, unknown> = {};
  obj["t"] = c.type;
  if (c.tools && c.tools.length > 0) obj["tools"] = [...c.tools];
  if (c.agent) obj["agent"] = c.agent;
  if (c.expiry) obj["exp"] = Math.trunc(c.expiry);
  if (c.maxCalls) obj["max_calls"] = Math.trunc(c.maxCalls);
  return new TextEncoder().encode(JSON.stringify(obj));
}

function b64urlDecode(s: string): Uint8Array {
  const standard = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = standard.length % 4 === 0 ? "" : "=".repeat(4 - (standard.length % 4));
  return new Uint8Array(Buffer.from(standard + pad, "base64"));
}

function b64urlEncode(b: Uint8Array): string {
  return Buffer.from(b)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac("sha256", key).update(data).digest());
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Produce a token whose signature is a known HMAC chain seeded from
 * a fake master key. Mirrors gateway capability v3 (gateway 0.9+):
 * `tenant` is signed into the canonical payload between `iss` and
 * `sub`, exactly as the Go gateway emits it.
 */
function makeFakeParent({
  jti = "root-jti-1",
  tenant = "default",
}: { jti?: string; tenant?: string } = {}): string {
  const masterKey = new Uint8Array(32).fill(0x78); // "x" repeated, matches Python fixture

  // canonicalPayload field order (matches gateway/internal/capability/token.go):
  //   v, jti, root_jti, iss, tenant, sub, iat
  const payloadObj: Record<string, unknown> = {
    v: 3,
    jti,
    root_jti: jti,
    iss: "intentgate",
    tenant,
    sub: "agent-x",
    iat: 1_700_000_000,
  };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payloadObj));
  let sig = hmacSha256(masterKey, payloadBytes);

  // Mint always prepends an agent_lock caveat. Hop the chain one step.
  const lock: Caveat = { type: CaveatType.AGENT_LOCK, agent: "agent-x" };
  sig = hmacSha256(sig, canonicalCaveatBytes(lock));

  const token: Record<string, unknown> = {
    v: 3,
    jti,
    root_jti: jti,
    iss: "intentgate",
    tenant,
    sub: "agent-x",
    iat: 1_700_000_000,
    cav: [{ t: "agent_lock", agent: "agent-x" }],
    sig: b64urlEncode(sig),
  };
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(token)));
}

// --- Caveat canonical bytes -------------------------------------------

describe("canonical caveat bytes", () => {
  it("encodes tool_allow with explicit field order", () => {
    const out = canonicalCaveatBytes({
      type: CaveatType.TOOL_ALLOW,
      tools: ["search", "read"],
    });
    expect(new TextDecoder().decode(out)).toBe(
      '{"t":"tool_allow","tools":["search","read"]}',
    );
  });

  it("encodes max_calls", () => {
    const out = canonicalCaveatBytes({ type: CaveatType.MAX_CALLS, maxCalls: 10 });
    expect(new TextDecoder().decode(out)).toBe('{"t":"max_calls","max_calls":10}');
  });

  it("encodes expiry", () => {
    const out = canonicalCaveatBytes({ type: CaveatType.EXPIRY, expiry: 1_700_000_000 });
    expect(new TextDecoder().decode(out)).toBe('{"t":"exp","exp":1700000000}');
  });

  it("omits empty fields (matches Go's omitempty)", () => {
    const out = canonicalCaveatBytes({
      type: CaveatType.AGENT_LOCK,
      agent: "agent-x",
      // tools, expiry, maxCalls all unset / falsy
    });
    expect(new TextDecoder().decode(out)).toBe('{"t":"agent_lock","agent":"agent-x"}');
  });

  it("preserves canonical field order regardless of input order", () => {
    // Pass fields in non-canonical order; output must still be canonical.
    const out = canonicalCaveatBytes({
      maxCalls: 5,
      type: CaveatType.MAX_CALLS,
    });
    expect(new TextDecoder().decode(out)).toBe('{"t":"max_calls","max_calls":5}');
  });
});

// --- Token round-trip --------------------------------------------------

describe("attenuate", () => {
  it("appends a caveat and chains the signature", () => {
    const parentStr = makeFakeParent();
    const parent = decodeToken(parentStr);
    const parentSig = b64urlDecode(parent["sig"] as string);

    const childStr = attenuate(parentStr, { addTools: ["read"] });
    const child = decodeToken(childStr);

    const parentCav = parent["cav"] as unknown[];
    const childCav = child["cav"] as Record<string, unknown>[];

    expect(childCav.length).toBe(parentCav.length + 1);
    expect(childCav[childCav.length - 1]).toEqual({
      t: "tool_allow",
      tools: ["read"],
    });

    // Child signature MUST equal HMAC(parent.sig, canonical(new_caveat)).
    const expected = hmacSha256(
      parentSig,
      canonicalCaveatBytes({ type: CaveatType.TOOL_ALLOW, tools: ["read"] }),
    );
    expect(bytesEqual(b64urlDecode(child["sig"] as string), expected)).toBe(true);
  });

  it("preserves root_jti and subject", () => {
    const parentStr = makeFakeParent({ jti: "root-A" });
    const childStr = attenuate(parentStr, { addTools: ["read"] });
    const child = decodeToken(childStr);
    expect(child["root_jti"]).toBe("root-A");
    expect(child["sub"]).toBe("agent-x");
  });

  it("preserves the parent's tenant claim", () => {
    // Tenancy is signed in the chain seed; the SDK just propagates
    // the field. The gateway enforces it cryptographically — we only
    // assert that we don't accidentally rewrite it.
    const parentStr = makeFakeParent({ jti: "root-A", tenant: "acme" });
    const childStr = attenuate(parentStr, { addTools: ["read"] });
    const child = decodeToken(childStr);
    expect(child["tenant"]).toBe("acme");
  });

  it("rejects tokens without a tenant (gateway < v0.9)", () => {
    // Pre-v3 token (no tenant field). Sign over a deliberately wrong
    // payload so we never accidentally accept it.
    const legacyV2: Record<string, unknown> = {
      v: 2,
      jti: "old-jti",
      root_jti: "old-jti",
      iss: "intentgate",
      sub: "agent-x",
      iat: 1_700_000_000,
      cav: [],
      sig: b64urlEncode(new Uint8Array(32).fill(0x78)),
    };
    const encoded = b64urlEncode(new TextEncoder().encode(JSON.stringify(legacyV2)));
    expect(() => attenuate(encoded, { addTools: ["read"] })).toThrow(
      AttenuationError,
    );
    expect(() => attenuate(encoded, { addTools: ["read"] })).toThrow(/tenant/);
  });

  it("walks the chain across multiple caveats in one call", () => {
    // Two attenuation hops at once: maxCalls then expiresAt. Each
    // generates one caveat, in that order, and the chain hops twice.
    const parentStr = makeFakeParent();
    const parent = decodeToken(parentStr);
    const parentCav = parent["cav"] as unknown[];

    const childStr = attenuate(parentStr, {
      maxCalls: 5,
      expiresAt: 1_800_000_000,
    });
    const child = decodeToken(childStr);
    const childCav = child["cav"] as Record<string, unknown>[];

    expect(childCav.length).toBe(parentCav.length + 2);
    expect(childCav[childCav.length - 2]?.["t"]).toBe("max_calls");
    expect(childCav[childCav.length - 1]?.["t"]).toBe("exp");
  });

  it("requires at least one narrowing argument", () => {
    const parentStr = makeFakeParent();
    expect(() => attenuate(parentStr, {})).toThrow(AttenuationError);
  });

  it("rejects negative maxCalls", () => {
    const parentStr = makeFakeParent();
    expect(() => attenuate(parentStr, { maxCalls: -1 })).toThrow(/maxCalls/);
  });

  it("decodeToken parses the cav array and tenant", () => {
    const parentStr = makeFakeParent({ tenant: "globex" });
    const parsed = decodeToken(parentStr);
    expect(parsed["tenant"]).toBe("globex");
    expect(Array.isArray(parsed["cav"])).toBe(true);
  });
});
