/**
 * Tests for the memory provenance module.
 *
 * The critical assertion is the cross-implementation KAT: TypeScript's
 * HKDF and length-prefixed Canonical bytes must match the Go gateway's
 * output byte-for-byte AND the Python SDK's output byte-for-byte. If
 * any of three drifts, the SDK and gateway will silently disagree on
 * HMACs and no test in any single codebase will catch it without this
 * one.
 *
 * The HKDF KAT vector here is the same value pinned in:
 *   - gateway/internal/provenance/provenance_test.go (TestDeriveSessionKey_KnownAnswer)
 *   - sdk-python/tests/test_memory.py (test_hkdf_kat_matches_go_gateway)
 */

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  type Envelope,
  MemoryProvenanceError,
  MemoryStore,
  SESSION_KEY_SIZE,
  ZERO_HASH,
  canonical,
  deriveSessionKey,
  sign,
  verify,
  verifyChain,
} from "../src/memory.js";

// ---------------------------------------------------------------------------
// Cross-implementation KAT — the most important test in this file
// ---------------------------------------------------------------------------

describe("HKDF cross-implementation KAT", () => {
  it("matches the Go gateway and Python SDK byte-for-byte", () => {
    const master = Buffer.from("intentgate-test-master-key-32-by", "utf8");
    const sessionId = "test-session-jti-abc";
    const expectedHex = "e8b49e3464de329ffdf2bdb5e3e557a762281292daab04b0fc8b6aede03a422e";

    const got = deriveSessionKey(master, sessionId);
    expect(got.length).toBe(SESSION_KEY_SIZE);
    expect(got.toString("hex")).toBe(expectedHex);
  });

  it("is deterministic", () => {
    const m = Buffer.from("master-key-bytes-here-okay");
    expect(deriveSessionKey(m, "session-1")).toEqual(deriveSessionKey(m, "session-1"));
  });

  it("produces distinct keys for distinct sessions", () => {
    const m = Buffer.from("master-key-bytes-here-okay");
    expect(deriveSessionKey(m, "session-A")).not.toEqual(deriveSessionKey(m, "session-B"));
  });

  it("rejects empty inputs", () => {
    expect(() => deriveSessionKey(Buffer.alloc(0), "s")).toThrow(/masterKey is empty/);
    expect(() => deriveSessionKey(Buffer.from("k"), "")).toThrow(/sessionId is empty/);
  });
});

// ---------------------------------------------------------------------------
// Canonical bytes — cross-implementation-critical
// ---------------------------------------------------------------------------

describe("canonical", () => {
  const base: Omit<Envelope, "hmac"> = {
    id: "01HG-test-id",
    sessionId: "jti-abc",
    timestamp: 1716530400000,
    data: Buffer.from('{"vendor":"Acme","account":"NL00ACME0000000001"}'),
    prevHash: ZERO_HASH,
  };

  it("is deterministic", () => {
    expect(canonical(base)).toEqual(canonical(base));
  });

  it.each([
    ["id", { ...base, id: "different" }],
    ["sessionId", { ...base, sessionId: "different" }],
    ["timestamp", { ...base, timestamp: 0 }],
    ["data", { ...base, data: Buffer.from("different") }],
    ["prevHash", { ...base, prevHash: Buffer.alloc(32, 0x99) }],
  ])("distinguishes %s", (_name, modified) => {
    expect(canonical(base).equals(canonical(modified))).toBe(false);
  });

  it("matches the documented byte layout spot-check", () => {
    // Timestamp value chosen to exercise all 8 byte positions of the
    // big-endian uint64 encoding while staying within
    // Number.MAX_SAFE_INTEGER (2^53 - 1). Real Unix-millisecond
    // timestamps are well under this limit for the next ~285,000
    // years, so production code is unaffected; a literal like
    // 0x0102030405060708 silently loses its low bits to JS number
    // precision before canonical() even sees it.
    const e: Omit<Envelope, "hmac"> = {
      id: "a",
      sessionId: "b",
      timestamp: 0x12345678abcdef, // = 5124095575370735, safely representable
      data: Buffer.from("xy"),
      prevHash: ZERO_HASH,
    };
    const out = canonical(e);
    // 4 + 1 + 4 + 1 + 8 + 4 + 32 + 4 + 2 = 60
    expect(out.length).toBe(60);
    expect(out.subarray(0, 4)).toEqual(Buffer.from([0x00, 0x00, 0x00, 0x01]));
    expect(out.subarray(4, 5).toString()).toBe("b");
    expect(out.subarray(5, 9)).toEqual(Buffer.from([0x00, 0x00, 0x00, 0x01]));
    expect(out.subarray(9, 10).toString()).toBe("a");
    // 0x12345678abcdef as 64-bit BE → 00 12 34 56 78 ab cd ef
    expect(out.subarray(10, 18)).toEqual(
      Buffer.from([0x00, 0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef]),
    );
    expect(out.subarray(18, 22)).toEqual(Buffer.from([0x00, 0x00, 0x00, 0x20]));
    expect(out.subarray(22, 54)).toEqual(ZERO_HASH);
    expect(out.subarray(54, 58)).toEqual(Buffer.from([0x00, 0x00, 0x00, 0x02]));
    expect(out.subarray(58, 60).toString()).toBe("xy");
  });
});

// ---------------------------------------------------------------------------
// Sign / Verify
// ---------------------------------------------------------------------------

describe("sign + verify", () => {
  it("round-trips a valid envelope", () => {
    const key = deriveSessionKey(Buffer.from("some-master-key-bytes-foobarbaz"), "s1");
    const signed = sign(key, {
      id: "e0",
      sessionId: "s1",
      timestamp: 1,
      data: Buffer.from("hello"),
      prevHash: ZERO_HASH,
    });
    expect(signed.hmac.length).toBe(32);
    expect(() => verify(key, signed)).not.toThrow();
  });

  it("detects data tamper — the textbook sophisticated AAI03 case", () => {
    const key = deriveSessionKey(Buffer.from("some-master-key-bytes-foobarbaz"), "tamper");
    const signed = sign(key, {
      id: "e0",
      sessionId: "tamper",
      timestamp: 1,
      data: Buffer.from('{"vendor":"Acme","account":"NL00ACME0000000001"}'),
      prevHash: ZERO_HASH,
    });
    const tampered: Envelope = {
      ...signed,
      data: Buffer.from('{"vendor":"Acme","account":"NL66ATTACKER000000"}'),
    };
    expect(() => verify(key, tampered)).toThrow(MemoryProvenanceError);
    expect(() => verify(key, tampered)).toThrow(/hmac mismatch/);
  });

  it("detects wrong session key", () => {
    const master = Buffer.from("master-bytes-padded-out-just-enough");
    const keyA = deriveSessionKey(master, "A");
    const keyB = deriveSessionKey(master, "B");
    const signed = sign(keyA, {
      id: "e0",
      sessionId: "A",
      timestamp: 1,
      data: Buffer.from("x"),
      prevHash: ZERO_HASH,
    });
    expect(() => verify(keyB, signed)).toThrow(MemoryProvenanceError);
  });

  it("rejects short HMAC", () => {
    const key = deriveSessionKey(Buffer.from("key-padding-here-okay-fine-just-do"), "s");
    expect(() =>
      verify(key, {
        id: "e",
        sessionId: "s",
        timestamp: 1,
        data: Buffer.from("x"),
        prevHash: ZERO_HASH,
        hmac: Buffer.from([1, 2]),
      }),
    ).toThrow(/hmac field is 2 bytes/);
  });

  it("rejects empty session key", () => {
    const env: Envelope = {
      id: "e",
      sessionId: "s",
      timestamp: 1,
      data: Buffer.from("x"),
      prevHash: ZERO_HASH,
      hmac: Buffer.alloc(32),
    };
    expect(() => verify(Buffer.alloc(0), env)).toThrow(/sessionKey is empty/);
    expect(() =>
      sign(Buffer.alloc(0), {
        id: "e",
        sessionId: "s",
        timestamp: 1,
        data: Buffer.from("x"),
        prevHash: ZERO_HASH,
      }),
    ).toThrow(/sessionKey is empty/);
  });
});

// ---------------------------------------------------------------------------
// VerifyChain
// ---------------------------------------------------------------------------

describe("verifyChain", () => {
  const master = Buffer.from("master-padding-bytes-here-please-ok");

  it("accepts a happy-path chain", () => {
    const key = deriveSessionKey(master, "chain");
    const e0 = sign(key, {
      id: "e0",
      sessionId: "chain",
      timestamp: 1,
      data: Buffer.from("first"),
      prevHash: ZERO_HASH,
    });
    const h0 = createHash("sha256").update(canonical(e0)).digest();
    const e1 = sign(key, {
      id: "e1",
      sessionId: "chain",
      timestamp: 2,
      data: Buffer.from("second"),
      prevHash: h0,
    });
    expect(() => verifyChain(key, [e0, e1])).not.toThrow();
  });

  it("detects a broken link", () => {
    const key = deriveSessionKey(master, "broken");
    const e0 = sign(key, {
      id: "e0",
      sessionId: "broken",
      timestamp: 1,
      data: Buffer.from("first"),
      prevHash: ZERO_HASH,
    });
    const e1 = sign(key, {
      id: "e1",
      sessionId: "broken",
      timestamp: 2,
      data: Buffer.from("second"),
      prevHash: Buffer.alloc(32, 0xab),
    });
    expect(() => verifyChain(key, [e0, e1])).toThrow(MemoryProvenanceError);
  });

  it("rejects first entry with non-zero prevHash", () => {
    const key = deriveSessionKey(master, "first");
    const e0 = sign(key, {
      id: "e0",
      sessionId: "first",
      timestamp: 1,
      data: Buffer.from("x"),
      prevHash: Buffer.alloc(32, 0xcc),
    });
    expect(() => verifyChain(key, [e0])).toThrow(MemoryProvenanceError);
  });

  it("accepts empty chain", () => {
    const key = deriveSessionKey(master, "empty");
    expect(() => verifyChain(key, [])).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — agent-side facade
// ---------------------------------------------------------------------------

describe("MemoryStore", () => {
  function newStore(): MemoryStore {
    const key = deriveSessionKey(Buffer.from("store-test-master-key-padding-okay"), "store-jti");
    return new MemoryStore("store-jti", key);
  }

  it("round-trips write then read", () => {
    const store = newStore();
    const eid = store.write({ vendor: "Acme", account: "NL00ACME0000" });
    const env = store.read(eid);
    expect(env.id).toBe(eid);
    expect(env.sessionId).toBe("store-jti");
    expect(JSON.parse(env.data.toString("utf8"))).toEqual({
      vendor: "Acme",
      account: "NL00ACME0000",
    });
  });

  it("read of unknown id throws", () => {
    const store = newStore();
    expect(() => store.read("does-not-exist")).toThrow(/not found/);
  });

  it("accepts bytes, strings, and objects", () => {
    const store = newStore();
    const a = store.write(Buffer.from([0, 1, 2]));
    const b = store.write("hello world");
    const c = store.write({ a: 1 });
    expect(store.read(a).data).toEqual(Buffer.from([0, 1, 2]));
    expect(store.read(b).data.toString()).toBe("hello world");
    // Sorted-keys + no-whitespace JSON to match Python SDK
    expect(store.read(c).data.toString()).toBe('{"a":1}');
  });

  it("chains consecutive writes", () => {
    const store = newStore();
    const a = store.write({ step: 1 });
    const b = store.write({ step: 2 });
    const ea = store.read(a);
    const eb = store.read(b);
    const expectedPrev = createHash("sha256").update(canonical(ea)).digest();
    expect(eb.prevHash).toEqual(expectedPrev);
  });

  it("detects storage-layer tamper", () => {
    const storage = new Map<string, Envelope>();
    const key = deriveSessionKey(Buffer.from("backend-test-padding-bytes-okay-ya"), "tamper-jti");
    const store = new MemoryStore("tamper-jti", key, {
      writeHook: (id, env) => storage.set(id, env),
      readHook: (id) => {
        const env = storage.get(id);
        if (!env) throw new Error(`not found: ${id}`);
        return env;
      },
    });
    const eid = store.write({ vendor: "Acme", account: "NL00ACME0000000001" });

    // Attacker swaps the data field in the backing store but keeps the HMAC.
    const original = storage.get(eid);
    if (!original) throw new Error("test setup");
    storage.set(eid, {
      ...original,
      data: Buffer.from('{"vendor":"Acme","account":"NL66ATTACKER0"}'),
    });

    expect(() => store.read(eid)).toThrow(MemoryProvenanceError);
  });

  it("provenanceFor produces the wire shape", () => {
    const store = newStore();
    const eid = store.write({ payload: "x" });
    const entries = store.provenanceFor([eid]);
    expect(entries.length).toBe(1);
    const w = entries[0]!;
    expect(w.id).toBe(eid);
    expect(w.session_id).toBe("store-jti");
    // base64url-no-padding round-trip
    expect(Buffer.from(w.data, "base64url").toString()).toBe('{"payload":"x"}');
    expect(Buffer.from(w.hmac, "base64url").length).toBe(32);
  });

  it("rejects wrong-size signing key", () => {
    expect(() => new MemoryStore("s", Buffer.from("too-short"))).toThrow(/must be 32 bytes/);
  });

  it("works with a custom backend", () => {
    const storage = new Map<string, Envelope>();
    const key = deriveSessionKey(Buffer.from("backend-test-padding-bytes-okay-ya"), "backend-jti");
    const store = new MemoryStore("backend-jti", key, {
      writeHook: (id, env) => storage.set(id, env),
      readHook: (id) => {
        const env = storage.get(id);
        if (!env) throw new Error("missing");
        return env;
      },
    });
    const eid = store.write({ backend: "custom" });
    expect(storage.has(eid)).toBe(true);
    expect(store.read(eid).id).toBe(eid);
  });
});
