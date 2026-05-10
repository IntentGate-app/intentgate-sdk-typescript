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
}

export interface GatewayOptions {
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
 * import { Gateway } from "@netgnarus/intentgate";
 *
 * const gw = new Gateway("http://localhost:8080", {
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
  private readonly token: string | undefined;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private nextId = 1;

  constructor(url: string, opts: GatewayOptions = {}) {
    if (!url) {
      throw new Error("Gateway: url is required");
    }
    // Trailing-slash tolerant; we always append explicit paths.
    this.url = url.replace(/\/+$/, "");
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
    };
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }
    if (opts.intentPrompt) {
      headers["X-Intent-Prompt"] = opts.intentPrompt;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let resp: Response;
    try {
      resp = await this.fetchImpl(`${this.url}/v1/mcp`, {
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
      throw new GatewayError(msg, { cause });
    } finally {
      clearTimeout(timer);
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
      throw new GatewayError("non-JSON response from gateway", { cause });
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
