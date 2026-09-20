/**
 * Tests for the Gateway client.
 *
 * We inject a fake fetch into the constructor to assert request shape
 * without standing up a gateway. The hot path through `toolCall` is
 * the same regardless of where the response comes from.
 */

import { describe, expect, it, vi } from "vitest";
import {
  CapabilityError,
  Gateway,
  GatewayError,
  IntentError,
  PolicyError,
  ROUTE_MCP_GOVERNED,
  ROUTE_MCP_LEGACY,
  UnavailableError,
  NEGOTIATION_HEADER,
  CANONICAL_ANSWER_VERSION,
} from "../src/index.js";

function makeOkResponse(extra: Record<string, unknown> = {}): Response {
  return new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      result: {
        content: [{ type: "text", text: "ok" }],
        isError: false,
        _intentgate: {
          decision: "allow",
          reason: "",
          check: "",
          latency_ms: 3,
        },
        ...extra,
      },
    }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

function makeRpcError(code: number, message = "denied", data: unknown = "reason"): Response {
  return new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      error: { code, message, data },
    }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

describe("Gateway.toolCall", () => {
  it("sends the JSON-RPC envelope with auth + intent prompt headers", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(makeOkResponse());
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_LEGACY,
      token: "tok-abc",
      fetch: fakeFetch as typeof fetch,
    });

    const result = await gw.toolCall("read_invoice", {
      arguments: { id: "123" },
      intentPrompt: "Process today's AP invoices",
    });

    expect(result.content).toEqual([{ type: "text", text: "ok" }]);
    expect(result.intentgate?.decision).toBe("allow");
    expect(result.intentgate?.latencyMs).toBe(3);

    // Inspect the call. We sent one POST to /v1/mcp with the right
    // body and headers.
    expect(fakeFetch).toHaveBeenCalledTimes(1);
    const [url, init] = fakeFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://gw.example/v1/mcp");
    expect(init.method).toBe("POST");

    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer tok-abc");
    expect(headers["X-Intent-Prompt"]).toBe("Process today's AP invoices");
    expect(headers["Content-Type"]).toBe("application/json");

    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body["method"]).toBe("tools/call");
    const params = body["params"] as Record<string, unknown>;
    expect(params["name"]).toBe("read_invoice");
    expect(params["arguments"]).toEqual({ id: "123" });
  });

  it("strips trailing slash from gateway URL", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(makeOkResponse());
    // S4-WP-22: the route is now named rather than defaulted. This test's subject is URL
    // construction, so it names the LEGACY route — the one it was written against — and its
    // assertion below is unchanged. Migrating it to the governed route would have altered
    // what it proves while appearing to be a mechanical edit.
    const gw = new Gateway("http://gw.example/", {
      route: ROUTE_MCP_LEGACY, fetch: fakeFetch as typeof fetch });
    await gw.toolCall("noop");
    const [url] = fakeFetch.mock.calls[0] as [string];
    expect(url).toBe("http://gw.example/v1/mcp");
  });

  it("throws CapabilityError on -32010", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(makeRpcError(-32010, "token expired"));
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_GOVERNED,
      token: "tok",
      fetch: fakeFetch as typeof fetch,
    });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(CapabilityError);
  });

  it("throws IntentError on -32011", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(makeRpcError(-32011));
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_GOVERNED, fetch: fakeFetch as typeof fetch });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(IntentError);
  });

  it("throws PolicyError on -32012", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(makeRpcError(-32012));
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_GOVERNED, fetch: fakeFetch as typeof fetch });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(PolicyError);
  });

  it("translates a transport failure into GatewayError", async () => {
    const fakeFetch = vi.fn().mockRejectedValue(new TypeError("ECONNREFUSED"));
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_GOVERNED, fetch: fakeFetch as typeof fetch });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(GatewayError);
  });

  it("translates a non-2xx HTTP status into GatewayError", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(
      new Response("server unhappy", { status: 502 }),
    );
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_GOVERNED, fetch: fakeFetch as typeof fetch });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(GatewayError);
  });

  it("rejects an empty tool name early", async () => {
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_GOVERNED, fetch: vi.fn() as unknown as typeof fetch });
    await expect(gw.toolCall("")).rejects.toThrow(/tool is required/);
  });

  it("uses sequential request ids by default", async () => {
    // mockImplementation returns a fresh Response per call. (mockResolvedValue
    // would resolve with the SAME object every time, and .json() consumes
    // the body — the second toolCall would then 500-equivalent.)
    const fakeFetch = vi.fn().mockImplementation(() => Promise.resolve(makeOkResponse()));
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_GOVERNED, fetch: fakeFetch as typeof fetch });
    await gw.toolCall("a");
    await gw.toolCall("b");
    const ids = fakeFetch.mock.calls.map((c) => {
      const [, init] = c as [string, RequestInit];
      return (JSON.parse(init.body as string) as Record<string, unknown>)["id"];
    });
    expect(ids).toEqual([1, 2]);
  });
});

/**
 * S4-WP-22 · negotiation and the UNAVAILABLE outcome — the TypeScript half.
 *
 * Held in parity with sdk-python's tests of the same name. Two frozen rulings, and until
 * 2026-09-20 neither was wired in either SDK:
 *
 *   ODR-R1-053  "An unhonoured IGA/1 negotiation produces an EXPLICIT fallback, never a
 *               silent one."
 *   ODR-R1-018  "NO ROUTE DEFAULT. UNAVAILABLE remains an OUTCOME, never another durable
 *               verdict."
 *
 * NEGOTIATION_HEADER was defined and exported by both SDKs and sent by neither, and
 * UnavailableError was exported and thrown nowhere while GatewayError carried its exact
 * documented meaning.
 */
describe("S4-WP-22 negotiation and the UNAVAILABLE outcome", () => {
  it("N1 asks for the contract on every call", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(makeOkResponse());
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_GOVERNED, fetch: fakeFetch as typeof fetch });
    await gw.toolCall("any");
    const init = fakeFetch.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers[NEGOTIATION_HEADER]).toBe(CANONICAL_ANSWER_VERSION);
  });

  it("N1b NON-VACUITY: the header map carries more than the one asserted header", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(makeOkResponse());
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_GOVERNED, fetch: fakeFetch as typeof fetch });
    await gw.toolCall("any");
    const init = fakeFetch.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("N2 a transport failure is UNAVAILABLE, not a denial", async () => {
    const fakeFetch = vi.fn().mockRejectedValue(new TypeError("ECONNREFUSED"));
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_GOVERNED, fetch: fakeFetch as typeof fetch });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(UnavailableError);
  });

  it("N3 an unreadable answer is UNAVAILABLE", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(
      new Response("not json at all", { status: 200 }),
    );
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_GOVERNED, fetch: fakeFetch as typeof fetch });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(UnavailableError);
  });

  it("N4 an ANSWERED error is NOT unavailable — the distinction the ruling preserves", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(
      new Response("upstream down", { status: 503 }),
    );
    const gw = new Gateway("http://gw.example", {
      route: ROUTE_MCP_GOVERNED, fetch: fakeFetch as typeof fetch });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(GatewayError);
    await expect(gw.toolCall("any")).rejects.not.toBeInstanceOf(UnavailableError);
  });

  it("N5 COMPATIBILITY: the ruled outcome is still a GatewayError", () => {
    // What let the outcome be thrown at all without a breaking change, asserted rather than
    // assumed — the benefit disappears if the hierarchy is ever flattened.
    expect(new UnavailableError("x")).toBeInstanceOf(GatewayError);
  });
});
