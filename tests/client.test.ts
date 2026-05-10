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
    const gw = new Gateway("http://gw.example/", { fetch: fakeFetch as typeof fetch });
    await gw.toolCall("noop");
    const [url] = fakeFetch.mock.calls[0] as [string];
    expect(url).toBe("http://gw.example/v1/mcp");
  });

  it("throws CapabilityError on -32010", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(makeRpcError(-32010, "token expired"));
    const gw = new Gateway("http://gw.example", {
      token: "tok",
      fetch: fakeFetch as typeof fetch,
    });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(CapabilityError);
  });

  it("throws IntentError on -32011", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(makeRpcError(-32011));
    const gw = new Gateway("http://gw.example", { fetch: fakeFetch as typeof fetch });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(IntentError);
  });

  it("throws PolicyError on -32012", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(makeRpcError(-32012));
    const gw = new Gateway("http://gw.example", { fetch: fakeFetch as typeof fetch });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(PolicyError);
  });

  it("translates a transport failure into GatewayError", async () => {
    const fakeFetch = vi.fn().mockRejectedValue(new TypeError("ECONNREFUSED"));
    const gw = new Gateway("http://gw.example", { fetch: fakeFetch as typeof fetch });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(GatewayError);
  });

  it("translates a non-2xx HTTP status into GatewayError", async () => {
    const fakeFetch = vi.fn().mockResolvedValue(
      new Response("server unhappy", { status: 502 }),
    );
    const gw = new Gateway("http://gw.example", { fetch: fakeFetch as typeof fetch });
    await expect(gw.toolCall("any")).rejects.toBeInstanceOf(GatewayError);
  });

  it("rejects an empty tool name early", async () => {
    const gw = new Gateway("http://gw.example", { fetch: vi.fn() as unknown as typeof fetch });
    await expect(gw.toolCall("")).rejects.toThrow(/tool is required/);
  });

  it("uses sequential request ids by default", async () => {
    // mockImplementation returns a fresh Response per call. (mockResolvedValue
    // would resolve with the SAME object every time, and .json() consumes
    // the body — the second toolCall would then 500-equivalent.)
    const fakeFetch = vi.fn().mockImplementation(() => Promise.resolve(makeOkResponse()));
    const gw = new Gateway("http://gw.example", { fetch: fakeFetch as typeof fetch });
    await gw.toolCall("a");
    await gw.toolCall("b");
    const ids = fakeFetch.mock.calls.map((c) => {
      const [, init] = c as [string, RequestInit];
      return (JSON.parse(init.body as string) as Record<string, unknown>)["id"];
    });
    expect(ids).toEqual([1, 2]);
  });
});
