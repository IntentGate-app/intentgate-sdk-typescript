/**
 * HTTP client for the IntentGate gateway.
 *
 * The {@link Gateway} class wraps the JSON-RPC envelope, the
 * Authorization header, and the X-Intent-Prompt header so callers
 * invoke `gw.toolCall(...)` like any other method and have errors
 * materialize as typed exceptions.
 *
 * Zero runtime deps: uses Node 18+'s native `fetch`. If you need to
 * run on older Node or in an environment without fetch, supply your
 * own fetch-shaped function via the `fetch` constructor option.
 */

import {
  BudgetError,
  CapabilityError,
  GatewayError,
  IntentError,
  IntentGateError,
  PolicyError,
  ProtocolError,
  forCode,
} from "./errors.js";
import {
  CANONICAL_ANSWER_VERSION,
  NEGOTIATION_HEADER,
  UnavailableError,
} from "./decision.js";

const TOOLS_CALL_METHOD = "tools/call";
const DEFAULT_TIMEOUT_MS = 10_000;

/** One piece of the tool's response, in MCP shape. */
export interface ContentBlock {
  type: string;
  text?: string;
}

/**
 * Per-call gateway decision metadata, lifted from the `_intentgate`
 * vendor extension on the JSON-RPC result. Always present on a
 * successful tool_call; the gateway populates it on every allow.
 */
export interface IntentGateMetadata {
  decision: string;
  reason: string;
  check: string;
  latencyMs: number;
}

/** Successful tool-call response. */
export interface ToolCallResult {
  content: ContentBlock[];
  /** Tool's own `isError` flag — distinct from gateway transport errors. */
  isError: boolean;
  intentgate: IntentGateMetadata | null;
}

export interface ToolCallOptions {
  /** Tool arguments. The gateway logs only the keys, never the values. */
  arguments?: Record<string, unknown>;

  /**
   * The user's original prompt. Sent in `X-Intent-Prompt`; the gateway
   * feeds it to the intent extractor and verifies the requested tool
   * is consistent with the extracted intent. Optional, but strongly
   * recommended in production — without it the intent check is
   * skipped (or denies in strict mode).
   */
  intentPrompt?: string;

  /**
   * JSON-RPC request id. When unset, the Gateway uses a sequential
   * per-instance counter — fine for most agents.
   */
  requestId?: number | string;

  /**
   * Optional list of memory entry IDs that influenced this tool call.
   * When supplied together with `memoryStore`, the SDK looks up the
   * corresponding signed envelopes and packs them into the
   * `X-Intent-Memory-Provenance` header. The gateway re-derives the
   * session signing key from the capability token's jti, verifies
   * each HMAC, and walks the chain — closing the sophisticated AAI03
   * (Memory Poisoning) case. Used only when the gateway has
   * provenance enabled; otherwise the header is ignored. See
   * `MemoryStore`.
   */
  memoryProvenance?: readonly string[];

  /**
   * MemoryStore instance the SDK queries for the envelopes named in
   * `memoryProvenance`. Required iff `memoryProvenance` is non-empty.
   */
  memoryStore?: import("./memory.js").MemoryStore;
}

/** The legacy capability/bundle enforcement route. */
export const ROUTE_MCP_LEGACY = "/v1/mcp";

/** The governed BA-/IG- enforcement route, where the control-plane decision is the sole authority. */
export const ROUTE_MCP_GOVERNED = "/v1/mcp/ig";

/**
 * Raised when a Gateway is constructed without choosing a route.
 *
 *   [FROZEN] ODR-R1-018 (TIER_1): "NO ROUTE DEFAULT."
 *
 * The readiness report gives the reason in one clause: make it a required constructor argument
 * "so no consumer is silently moved between an audited and an unaudited path". /v1/mcp and
 * /v1/mcp/ig are not two spellings of one thing — the first runs the legacy capability/bundle
 * pipeline, the second is governed solely by the BA-/IG- chain. A default would move every
 * consumer from one authority to the other on an upgrade, and none of them would read a
 * changelog entry about it.
 *
 * THIS IS A BREAKING CHANGE AND IT IS SUPPOSED TO BE. A migration that fails at construction is
 * a migration somebody performs; a migration that succeeds silently is one that happens to
 * them.
 */
export class RouteNotChosenError extends IntentGateError {
  constructor() {
    super(
      "Gateway: `route` is required and has no default. Choose ROUTE_MCP_GOVERNED " +
        `("${ROUTE_MCP_GOVERNED}", the governed BA-/IG- chain) or ROUTE_MCP_LEGACY ` +
        `("${ROUTE_MCP_LEGACY}", the legacy capability/bundle pipeline). They are different ` +
        "authorities and the choice is yours to make, not this SDK's.",
      { code: 0 },
    );
    this.name = "RouteNotChosenError";
  }
}

/**
 * Raised when the chosen route is not mounted on this gateway.
 *
 * A distinct type rather than a GatewayError with a 404 in it, because the two are acted on
 * differently: this one is fixed in configuration and never by a policy change, and it must
 * never be mistaken for the gateway refusing the call.
 */
export class RouteNotFoundError extends IntentGateError {
  readonly route: string;
  constructor(route: string, detail?: unknown) {
    super(
      `gateway has no route ${route}: this is a configuration outcome, not a denial. ` +
        `Check the route passed to the Gateway constructor against what this deployment mounts.`,
      { code: 0, data: detail },
    );
    this.name = "RouteNotFoundError";
    this.route = route;
  }
}

export interface GatewayOptions {
  /**
   * WHICH ENFORCEMENT ROUTE THIS CLIENT TALKS TO. Required; there is no default.
   *
   * See {@link RouteNotChosenError}. Use {@link ROUTE_MCP_GOVERNED} or
   * {@link ROUTE_MCP_LEGACY}; any other path is accepted so a deployment can mount the
   * gateway elsewhere, and a 404 from it is reported as a configuration outcome rather than
   * as a denial — "the route is wrong" and "the policy said no" are different facts and only
   * one of them is fixed by editing config.
   */
  route: string;

  /**
   * Capability token from `igctl mint` or your tenant's mint service.
   * When omitted, no Authorization header is sent and the gateway
   * will reject with CapabilityError if it's in strict mode.
   */
  token?: string;

  /** Per-request timeout in milliseconds. Default 10s. */
  timeoutMs?: number;

  /**
   * Pluggable fetch implementation. Defaults to the global
   * `fetch` (Node 18+, browsers, and most modern runtimes). Useful
   * for test injection, custom transports, or shared connection
   * pooling.
   */
  fetch?: typeof fetch;
}

/**
 * Thin client for the IntentGate gateway.
 *
 * @example
 * ```ts
 * import { Gateway } from "@intentgate-app/intentgate";
 *
 * const gw = new Gateway("http://localhost:8080", {
 *   route: ROUTE_MCP_GOVERNED,
 *   token: process.env.INTENTGATE_TOKEN,
 * });
 * const result = await gw.toolCall("read_invoice", {
 *   arguments: { id: "123" },
 *   intentPrompt: "Process today's AP invoices",
 * });
 * ```
 */
export class Gateway {
  private readonly url: string;
  /** The chosen enforcement route. No default; see RouteNotChosenError. */
  readonly route: string;
  private readonly token: string | undefined;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private nextId = 1;

  constructor(url: string, opts: GatewayOptions) {
    if (!url) {
      throw new Error("Gateway: url is required");
    }
    // Checked at RUNTIME as well as in the type, because a JavaScript consumer has no type to
    // stop them and is exactly the consumer this refusal exists for.
    if (!opts || typeof opts.route !== "string" || opts.route.trim() === "") {
      throw new RouteNotChosenError();
    }
    // Trailing-slash tolerant; we always append explicit paths.
    // Loop instead of regex (`url.replace(/\/+$/, "")`) so we silence
    // CodeQL's polynomial-regex-on-uncontrolled-data warning. The
    // regex wasn't actually exploitable here (anchored, single-char
    // class, no backtracking), but a plain loop has no ReDoS class
    // at all.
    let cleaned = url;
    while (cleaned.endsWith("/")) cleaned = cleaned.slice(0, -1);
    this.url = cleaned;
    this.route = opts.route;
    this.token = opts.token;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    if (!this.fetchImpl) {
      throw new Error(
        "Gateway: no fetch available; pass `fetch` in options or run on Node 18+",
      );
    }
  }

  /**
   * Invoke a tool through the gateway.
   *
   * Resolves with a {@link ToolCallResult} for an allowed call. Throws
   * one of the typed errors (CapabilityError / IntentError /
   * PolicyError / BudgetError / ProtocolError / GatewayError) when
   * the gateway denies, the request fails to reach the gateway, or
   * the response isn't well-formed JSON-RPC.
   */
  async toolCall(tool: string, opts: ToolCallOptions = {}): Promise<ToolCallResult> {
    if (!tool) {
      throw new Error("toolCall: tool is required");
    }

    const id = opts.requestId ?? this.nextId++;
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: TOOLS_CALL_METHOD,
      params: {
        name: tool,
        arguments: opts.arguments ?? {},
      },
    });

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      // S4-WP-22 AC-1. ASK FOR THE CONTRACT, ALWAYS.
      //
      //     [FROZEN] ODR-R1-053: "An unhonoured IGA/1 negotiation produces an EXPLICIT
      //     fallback, never a silent one."
      //
      // Measured 2026-09-20: this header was DEFINED and EXPORTED by both SDKs and sent by
      // neither, and `answer.Negotiate` in the gateway has no callers outside its own tests. So
      // today every negotiation is unhonoured — which is precisely the case the ruling is about.
      // Sending it is what makes the fallback observable: a server that ignores it yields a
      // decision carrying `contractNegotiated: false` and a stated reason, instead of a legacy
      // answer nobody can tell apart from an honoured one.
      [NEGOTIATION_HEADER]: CANONICAL_ANSWER_VERSION,
    };
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }
    if (opts.intentPrompt) {
      headers["X-Intent-Prompt"] = opts.intentPrompt;
    }
    if (opts.memoryProvenance && opts.memoryProvenance.length > 0) {
      if (!opts.memoryStore) {
        throw new Error(
          "toolCall: memoryProvenance is non-empty but memoryStore is undefined; " +
            "supply a MemoryStore so the SDK can look up the envelopes",
        );
      }
      // Look up envelopes (verifies each locally), serialize the
      // wire entries, then base64url-encode the JSON array. Matches
      // the gateway's parser shape in
      // gateway/internal/handlers/mcp_provenance.go.
      const wireEntries = opts.memoryStore.provenanceFor(opts.memoryProvenance);
      headers["X-Intent-Memory-Provenance"] = Buffer.from(JSON.stringify(wireEntries)).toString(
        "base64url",
      );
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let resp: Response;
    try {
      resp = await this.fetchImpl(`${this.url}${this.route}`, {
        method: "POST",
        body,
        headers,
        signal: controller.signal,
      });
    } catch (cause) {
      // AbortError surfaces as a DOMException in browsers and a
      // plain Error in Node; either way `name === "AbortError"`.
      const isAbort = cause instanceof Error && cause.name === "AbortError";
      const msg = isAbort
        ? `gateway timed out after ${this.timeoutMs}ms`
        : `transport error reaching gateway: ${stringifyCause(cause)}`;
      // ODR-R1-018: UNAVAILABLE is an OUTCOME. The gateway could not be asked, so no answer
      // exists — a different fact from an answer that denied. UnavailableError extends
      // GatewayError, so code catching the older name is unaffected.
      throw new UnavailableError(msg, { cause });
    } finally {
      clearTimeout(timer);
    }

    if (resp.status === 404) {
      // S4-WP-22. A 404 ON THE CHOSEN ROUTE IS A CONFIGURATION FACT, NOT A DENIAL.
      //
      // The generic branch below would report it as a GatewayError like any other non-2xx,
      // and an operator reading "gateway returned HTTP 404" alongside a run of blocked calls
      // has every reason to think the gateway is refusing them. "The route is wrong" and "the
      // policy said no" are different facts and only one of them is fixed by editing config.
      const text = await safeText(resp);
      throw new RouteNotFoundError(this.route, text || resp.statusText);
    }

    if (!resp.ok) {
      const text = await safeText(resp);
      throw new GatewayError(`gateway returned HTTP ${resp.status}`, {
        data: text || resp.statusText,
      });
    }

    let payload: unknown;
    try {
      payload = await resp.json();
    } catch (cause) {
      // The other half of the same outcome: it answered something unreadable, so again no
      // answer exists. The class's own doc comment names both cases.
      throw new UnavailableError("non-JSON response from gateway", { cause });
    }

    return parseResponse(payload);
  }
}

function stringifyCause(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  return String(cause);
}

async function safeText(resp: Response): Promise<string> {
  try {
    const t = await resp.text();
    return t.slice(0, 500);
  } catch {
    return "";
  }
}

function parseResponse(payload: unknown): ToolCallResult {
  if (!isObject(payload)) {
    throw new ProtocolError("response is not a JSON object");
  }

  // Error branch: surface as the typed stage exception.
  const err = payload["error"];
  if (err != null) {
    if (!isObject(err)) {
      throw new ProtocolError("error field is not an object");
    }
    const code = typeof err["code"] === "number" ? err["code"] : 0;
    const message = typeof err["message"] === "string" ? err["message"] : "gateway error";
    const data = err["data"];
    const Cls = forCode(code) as new (
      message: string,
      opts?: { code?: number; data?: unknown },
    ) => IntentGateError;
    throw new Cls(message, { code, data });
    // (Cls is one of CapabilityError | IntentError | PolicyError |
    // BudgetError | ProtocolError; the union is collapsed in the
    // type system because forCode returns the base type, but every
    // member shares the same constructor signature.)
  }

  const result = payload["result"];
  if (!isObject(result)) {
    throw new ProtocolError("response missing 'result' object", { data: payload });
  }

  const rawContent = Array.isArray(result["content"]) ? result["content"] : [];
  const content: ContentBlock[] = [];
  for (const b of rawContent) {
    if (!isObject(b)) continue;
    content.push({
      type: typeof b["type"] === "string" ? b["type"] : "",
      text: typeof b["text"] === "string" ? b["text"] : undefined,
    });
  }

  let intentgate: IntentGateMetadata | null = null;
  const ig = result["_intentgate"];
  if (isObject(ig)) {
    intentgate = {
      decision: typeof ig["decision"] === "string" ? ig["decision"] : "",
      reason: typeof ig["reason"] === "string" ? ig["reason"] : "",
      check: typeof ig["check"] === "string" ? ig["check"] : "",
      latencyMs: typeof ig["latency_ms"] === "number" ? ig["latency_ms"] : 0,
    };
  }

  return {
    content,
    isError: result["isError"] === true,
    intentgate,
  };
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

// Re-export the error classes here too so a consumer that only
// imports from "./client" still gets the typed catch surface they
// need. The package's index.ts is the canonical entry point and
// re-exports these as well.
export {
  BudgetError,
  CapabilityError,
  GatewayError,
  IntentError,
  IntentGateError,
  PolicyError,
  ProtocolError,
};
