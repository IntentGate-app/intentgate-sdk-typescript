/**
 * Memory provenance primitives for the IntentGate TypeScript SDK.
 *
 * This module implements the SDK side of the AAI03 (Memory Poisoning)
 * defense. The agent wraps its memory backend (vector DB, Redis,
 * in-memory dict, anything) with {@link MemoryStore}, which signs
 * every write with an HMAC-SHA256 keyed by a per-session signing key
 * derived (via HKDF) from the capability token. At tool-call time the
 * agent declares which memory entries influenced the call via the
 * `memoryProvenance` parameter on `Gateway.toolCall`; the gateway
 * re-derives the session key and verifies each entry.
 *
 * # Cross-implementation contract
 *
 * The byte encoding of an {@link Envelope} (see {@link canonical})
 * MUST match the Go gateway's `internal/provenance.Canonical`
 * byte-for-byte AND match the Python SDK's `intentgate.memory.canonical`
 * byte-for-byte. The KDF MUST be HKDF-SHA256 with info=
 * `intentgate-memory-v1`. The HMAC MUST be HMAC-SHA256.
 *
 * Drift in any of these contracts means the SDK and the gateway
 * silently disagree on signatures — a class of bug caught by the
 * cross-implementation KAT test in `tests/memory.test.ts`. If you
 * change anything in this file, run that test against the Go gateway's
 * `TestDeriveSessionKey_KnownAnswer` and the Python SDK's
 * `test_hkdf_kat_matches_go_gateway` to confirm the wire contract
 * still holds.
 *
 * # Zero runtime dependencies
 *
 * Uses only `node:crypto` (createHmac, createHash, hkdfSync,
 * timingSafeEqual, randomUUID). No third-party crypto package. The
 * Node 18+ baseline is documented in package.json.
 */

import { createHmac, createHash, hkdfSync, timingSafeEqual, randomUUID } from "node:crypto";

// Version tag baked into the HKDF info parameter. Bumping this forces
// a key-derivation cutover: old and new keys are computed from the
// same master + jti but produce different bytes. Future versions
// could accept multiple labels during a grace window; v1 is the only
// one defined today.
const DERIVATION_INFO = Buffer.from("intentgate-memory-v1");

/** Length of a derived session signing key in bytes. Matches the Go
 * gateway's SessionKeySize and the Python SDK's SESSION_KEY_SIZE. */
export const SESSION_KEY_SIZE = 32;

/** Length of SHA-256 / HMAC-SHA256 output in bytes. */
const HASH_SIZE = 32;

/** The conventional PrevHash value for the first entry in a session.
 * Named so the special-case is obvious at the call site. */
export const ZERO_HASH: Buffer = Buffer.alloc(HASH_SIZE);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Raised when the SDK cannot produce or verify a memory envelope.
 * Distinct from the gateway-side `ProvenanceError` in `errors.ts`
 * (which is raised by `Gateway.toolCall` when the gateway rejected
 * the provenance check). This class is for SDK-internal failures —
 * a tampered entry detected at read time, a malformed envelope, etc.
 */
export class MemoryProvenanceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MemoryProvenanceError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// HKDF — wraps node:crypto's built-in hkdfSync
// ---------------------------------------------------------------------------

/**
 * Derive the per-session memory signing key.
 *
 * Matches the gateway's `provenance.DeriveSessionKey` and the Python
 * SDK's `derive_session_key`: HKDF-SHA256 with salt = `sessionId` (as
 * UTF-8 bytes), info = `intentgate-memory-v1`, length = 32.
 *
 * @throws if `masterKey` is empty or `sessionId` is empty.
 */
export function deriveSessionKey(masterKey: Buffer | Uint8Array, sessionId: string): Buffer {
  if (!masterKey || masterKey.length === 0) {
    throw new Error("deriveSessionKey: masterKey is empty");
  }
  if (!sessionId) {
    throw new Error("deriveSessionKey: sessionId is empty");
  }
  const out = hkdfSync(
    "sha256",
    masterKey,
    Buffer.from(sessionId, "utf8"),
    DERIVATION_INFO,
    SESSION_KEY_SIZE,
  );
  // node:crypto returns an ArrayBuffer; wrap as a Node Buffer for
  // ergonomic byte ops downstream (slice, equals, etc.).
  return Buffer.from(out);
}

// ---------------------------------------------------------------------------
// Envelope + canonical bytes
// ---------------------------------------------------------------------------

/** One signed memory entry. Stored opaquely by the customer's memory
 * backend; produced by `MemoryStore.write`; verified by the gateway. */
export interface Envelope {
  /** Stable identifier for the entry. */
  id: string;
  /** The capability token's `jti` whose signing key signed this. */
  sessionId: string;
  /** Creation time as Unix milliseconds. */
  timestamp: number;
  /** Application-level payload bytes. */
  data: Buffer;
  /** SHA-256 of the canonical bytes of the previous entry in this
   * session, or ZERO_HASH for the first entry. */
  prevHash: Buffer;
  /** HMAC-SHA256 of canonical(envelope) under the session key. */
  hmac: Buffer;
}

/**
 * Produce the byte sequence the envelope's HMAC covers.
 *
 * Encoding is a length-prefixed concatenation of the immutable fields
 * in order: sessionId (utf-8), id (utf-8), timestamp (big-endian
 * uint64), prevHash, data. Lengths are big-endian uint32.
 *
 * The encoding is deliberately NOT JSON — same byte sequence the Go
 * gateway produces in `provenance.Canonical` and the Python SDK
 * produces in `canonical`. Cross-verified by the KAT test.
 *
 * The `hmac` field is excluded (a signature cannot cover itself).
 */
export function canonical(env: Pick<Envelope, "id" | "sessionId" | "timestamp" | "data" | "prevHash">): Buffer {
  const sid = Buffer.from(env.sessionId, "utf8");
  const eid = Buffer.from(env.id, "utf8");

  // Total size: 4 + len(sid) + 4 + len(eid) + 8 + 4 + len(prevHash) + 4 + len(data)
  const total = 4 + sid.length + 4 + eid.length + 8 + 4 + env.prevHash.length + 4 + env.data.length;
  const out = Buffer.alloc(total);
  let off = 0;

  out.writeUInt32BE(sid.length, off);
  off += 4;
  sid.copy(out, off);
  off += sid.length;

  out.writeUInt32BE(eid.length, off);
  off += 4;
  eid.copy(out, off);
  off += eid.length;

  // Mirror Go's int64 → uint64 reinterpretation. JS numbers don't
  // safely represent the full int64 range, but Unix milliseconds
  // fit comfortably below Number.MAX_SAFE_INTEGER for ~285,000
  // years past 1970. We use writeBigUInt64BE with BigInt conversion
  // so the encoded bytes match Go's binary.BigEndian.PutUint64
  // regardless of sign.
  out.writeBigUInt64BE(BigInt(env.timestamp) & 0xffffffffffffffffn, off);
  off += 8;

  out.writeUInt32BE(env.prevHash.length, off);
  off += 4;
  env.prevHash.copy(out, off);
  off += env.prevHash.length;

  out.writeUInt32BE(env.data.length, off);
  off += 4;
  env.data.copy(out, off);

  return out;
}

/**
 * Return a copy of `env` with the `hmac` field populated.
 *
 * Used at memory-write time by `MemoryStore.write` and by tests.
 * Computes `HMAC-SHA256(sessionKey, canonical(env))`.
 *
 * @throws if `sessionKey` is empty.
 */
export function sign(sessionKey: Buffer, env: Omit<Envelope, "hmac">): Envelope {
  if (!sessionKey || sessionKey.length === 0) {
    throw new Error("sign: sessionKey is empty");
  }
  const mac = createHmac("sha256", sessionKey);
  mac.update(canonical(env));
  return { ...env, hmac: mac.digest() };
}

/**
 * Check `env.hmac` against `sessionKey`. Returns `undefined` on a
 * valid signature; throws {@link MemoryProvenanceError} otherwise.
 * Comparison uses `timingSafeEqual` — constant-time with respect to
 * signature contents.
 */
export function verify(sessionKey: Buffer, env: Envelope): void {
  if (!sessionKey || sessionKey.length === 0) {
    throw new Error("verify: sessionKey is empty");
  }
  if (env.hmac.length !== HASH_SIZE) {
    throw new MemoryProvenanceError(
      `hmac field is ${env.hmac.length} bytes; expected ${HASH_SIZE}`,
    );
  }
  const expected = createHmac("sha256", sessionKey).update(canonical(env)).digest();
  if (!timingSafeEqual(expected, env.hmac)) {
    throw new MemoryProvenanceError("hmac mismatch");
  }
}

/**
 * Check a list of envelopes as a per-session chain.
 *
 * Each entry's HMAC must verify and each entry's `prevHash` must
 * equal SHA-256 of the canonical bytes of the previous entry. The
 * first entry's `prevHash` must equal {@link ZERO_HASH}.
 *
 * Empty chain is valid (let policy decide whether absence of memory
 * provenance is a deny condition for the tool).
 */
export function verifyChain(sessionKey: Buffer, chain: readonly Envelope[]): void {
  if (chain.length === 0) {
    return;
  }
  for (let i = 0; i < chain.length; i++) {
    const env = chain[i];
    if (!env) continue;
    try {
      verify(sessionKey, env);
    } catch (e) {
      if (e instanceof MemoryProvenanceError) {
        throw new MemoryProvenanceError(`entry ${i}: ${e.message}`);
      }
      throw e;
    }
    let expectedPrev: Buffer;
    if (i === 0) {
      expectedPrev = ZERO_HASH;
    } else {
      const prev = chain[i - 1];
      if (!prev) continue;
      expectedPrev = createHash("sha256").update(canonical(prev)).digest();
    }
    if (!timingSafeEqual(expectedPrev, env.prevHash)) {
      throw new MemoryProvenanceError(
        `entry ${i}: prev_hash does not match previous entry's canonical hash`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// MemoryStore — agent-side facade
// ---------------------------------------------------------------------------

/** Customer-supplied write hook for a backing store. */
export type MemoryWriteHook = (entryId: string, env: Envelope) => void;

/** Customer-supplied read hook. Must throw if entry not found. */
export type MemoryReadHook = (entryId: string) => Envelope;

/**
 * Sign-on-write, verify-on-read wrapper around a memory backend.
 *
 * The customer plugs their underlying memory store (Pinecone, Redis,
 * pgvector, an in-memory Map, anything) into this wrapper by
 * supplying two callables: a write-hook and a read-hook. The wrapper
 * signs entries on write and verifies them on read, so a tampered
 * entry surfaces immediately at the agent's read site rather than
 * waiting until the gateway rejects the tool call.
 *
 * The default storage backend is an in-memory Map — suitable for SDK
 * tests, demos, and small agents. Production agents pass their real
 * backend's read/write callables.
 */
export class MemoryStore {
  private readonly sessionId: string;
  private readonly key: Buffer;
  private readonly fallback = new Map<string, Envelope>();
  private readonly writeHook?: MemoryWriteHook;
  private readonly readHook?: MemoryReadHook;
  private chainHead: Buffer = ZERO_HASH;

  /**
   * @param sessionId The `jti` of the capability token this store is bound to.
   *   Used as the HKDF salt to derive the signing key.
   * @param memorySigningKey The 32-byte signing key returned by
   *   `POST /v1/admin/mint` when `with_memory_signing_key: true`.
   * @param options Optional `writeHook` / `readHook` callables; when
   *   absent the wrapper uses an in-memory Map fallback.
   */
  constructor(
    sessionId: string,
    memorySigningKey: Buffer | Uint8Array,
    options: { writeHook?: MemoryWriteHook; readHook?: MemoryReadHook } = {},
  ) {
    if (!sessionId) {
      throw new Error("MemoryStore: sessionId is required");
    }
    if (memorySigningKey.length !== SESSION_KEY_SIZE) {
      throw new Error(
        `MemoryStore: memorySigningKey must be ${SESSION_KEY_SIZE} bytes, got ${memorySigningKey.length}`,
      );
    }
    this.sessionId = sessionId;
    this.key = Buffer.from(memorySigningKey);
    this.writeHook = options.writeHook;
    this.readHook = options.readHook;
  }

  /**
   * Sign `data` into a new envelope and store it. Returns the entry
   * ID, which the caller passes to `Gateway.toolCall` via the
   * `memoryProvenance` list.
   *
   * `data` may be a Buffer, a string (utf-8 encoded), or any JSON-
   * serializable value (encoded with sorted keys + no whitespace so
   * equivalent inputs produce identical envelope bytes).
   */
  write(data: Buffer | string | Record<string, unknown> | unknown[]): string {
    let payload: Buffer;
    if (Buffer.isBuffer(data)) {
      payload = data;
    } else if (typeof data === "string") {
      payload = Buffer.from(data, "utf8");
    } else {
      payload = Buffer.from(stableStringify(data), "utf8");
    }

    const entryId = randomUUID().replaceAll("-", "");
    const env = sign(this.key, {
      id: entryId,
      sessionId: this.sessionId,
      timestamp: Date.now(),
      data: payload,
      prevHash: this.chainHead,
    });

    if (this.writeHook !== undefined) {
      this.writeHook(entryId, env);
    } else {
      this.fallback.set(entryId, env);
    }

    this.chainHead = createHash("sha256").update(canonical(env)).digest();
    return entryId;
  }

  /**
   * Fetch and verify the envelope identified by `entryId`.
   *
   * @throws if the entry is missing (`Error`) or if the HMAC fails
   *   ({@link MemoryProvenanceError}, indicating the entry was
   *   tampered with after writing).
   */
  read(entryId: string): Envelope {
    let env: Envelope | undefined;
    if (this.readHook !== undefined) {
      env = this.readHook(entryId);
    } else {
      env = this.fallback.get(entryId);
      if (env === undefined) {
        throw new Error(`MemoryStore: entry ${entryId} not found`);
      }
    }
    verify(this.key, env);
    return env;
  }

  /**
   * Build the wire-format provenance entries for a tool call. Each
   * entry is verified before inclusion — if any envelope was tampered
   * with at the storage layer, {@link MemoryProvenanceError} is
   * raised here rather than at the gateway.
   *
   * The returned objects use base64url (no padding) encoding for byte
   * fields — same shape the Go gateway parses.
   */
  provenanceFor(entryIds: readonly string[]): Array<{
    id: string;
    session_id: string;
    ts: number;
    data: string;
    prev_hash: string;
    hmac: string;
  }> {
    return entryIds.map((eid) => {
      const env = this.read(eid);
      return {
        id: env.id,
        session_id: env.sessionId,
        ts: env.timestamp,
        data: env.data.toString("base64url"),
        prev_hash: env.prevHash.toString("base64url"),
        hmac: env.hmac.toString("base64url"),
      };
    });
  }

  /** Number of entries in the fallback in-memory store. */
  get size(): number {
    return this.fallback.size;
  }
}

/**
 * Deterministic JSON stringify with sorted keys and no whitespace.
 * Used by MemoryStore.write so two equivalent objects produce
 * byte-identical envelopes. Mirrors Python's
 * `json.dumps(d, sort_keys=True, separators=(",", ":"))`.
 */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return (
    "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k])).join(",") + "}"
  );
}
