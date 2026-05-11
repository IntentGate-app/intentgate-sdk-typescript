# IntentGate TypeScript SDK

[![CI](https://github.com/NetGnarus/intentgate-sdk-typescript/actions/workflows/ci.yml/badge.svg)](https://github.com/NetGnarus/intentgate-sdk-typescript/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@netgnarus/intentgate.svg)](https://www.npmjs.com/package/@netgnarus/intentgate)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Node 18+](https://img.shields.io/badge/node-%3E=18-339933.svg)](package.json)

TypeScript SDK for the [IntentGate](https://github.com/NetGnarus/intentgate-gateway) authorization gateway.

Three lines wraps any agent's tool call with capability + intent + policy + budget checks:

```ts
import { Gateway } from "@netgnarus/intentgate";

const gw = new Gateway("http://localhost:8080", {
  token: process.env.INTENTGATE_TOKEN,
});
const result = await gw.toolCall("read_invoice", {
  arguments: { id: "123" },
  intentPrompt: "Process today's AP invoices",
});
```

`toolCall` resolves with the tool's response when the gateway allows the call, and throws a typed exception (`CapabilityError`, `IntentError`, `PolicyError`, `BudgetError`) when it blocks. Network failures throw `GatewayError`.

**Zero runtime dependencies.** The SDK uses Node's native `fetch` (Node 18+) and `node:crypto` for HMAC. No third-party packages in `dependencies`.

---

## Install

```sh
npm install @netgnarus/intentgate
# or
pnpm add @netgnarus/intentgate
# or
yarn add @netgnarus/intentgate
```

Requires **Node 18+**. Works in browsers and edge runtimes that provide `fetch` and a `crypto.subtle`-equivalent (call sites that use `attenuate` need `node:crypto` so are Node-only today; `Gateway.toolCall` is portable).

## What you get

| Export | What it does |
| --- | --- |
| `Gateway` | HTTP client. `gw.toolCall(tool, opts)` invokes a tool through the gateway; throws typed errors on deny. |
| `attenuate` | Pure-TS capability attenuation. Derive a strictly-narrower child token from a parent without touching the gateway's master key. |
| `decodeToken` | Inspect a token's claims and caveats (no signature check; the gateway does that). |
| `IntentGateError` family | Typed catch surface — `CapabilityError`, `IntentError`, `PolicyError`, `BudgetError`, plus `GatewayError` (transport) and `ProtocolError` (malformed JSON-RPC). |

## Capability attenuation

A parent agent can derive a narrower token for a sub-agent in one call. The chained-HMAC signature means the sub-agent can't widen the chain — only narrow it further:

```ts
import { attenuate } from "@netgnarus/intentgate";

// Parent token allows [search, read, email] for the next hour.
// Child: only [search, read], one call max.
const child = attenuate(parentToken, {
  addTools: ["search", "read"],
  maxCalls: 1,
});

// Hand `child` to the sub-agent. The gateway will reject any call
// to `email` with a CapabilityError because the parent's tool_allow
// caveat plus the child's tool_allow caveat intersect at [search, read].
```

Available narrowings:

- `addTools: string[]` — `tool_allow` caveat (intersection)
- `denyTools: string[]` — `tool_deny` caveat (additive blacklist)
- `maxCalls: number` — `max_calls` caveat (the chain enforces the minimum)
- `expiresAt: number` (Unix seconds) or `expiresInSeconds: number` — `exp` caveat
- `extra: Caveat[]` — append arbitrary caveats (advanced)

## Error handling

```ts
import { Gateway, CapabilityError, IntentError, GatewayError } from "@netgnarus/intentgate";

try {
  const result = await gw.toolCall("delete_user", {
    arguments: { id: "u-123" },
    intentPrompt: "Onboard a new employee",
  });
  // ...
} catch (err) {
  if (err instanceof CapabilityError) {
    // Token rejected (signature, expiry, agent lock, tool whitelist).
  } else if (err instanceof IntentError) {
    // The user's prompt didn't authorize this tool.
  } else if (err instanceof GatewayError) {
    // Could not reach the gateway, or non-JSON-RPC response.
    console.error("gateway transport problem:", err.message);
  } else {
    throw err;
  }
}
```

Every error carries `code` (the JSON-RPC code: `-32010` capability, `-32011` intent, `-32012` policy, `-32013` budget) and `data` (the gateway's reason string).

## Testing your integration

The SDK accepts a custom `fetch` implementation via the `fetch` option, so you can drive `Gateway` from unit tests without standing up a real gateway:

```ts
import { vi } from "vitest";
import { Gateway } from "@netgnarus/intentgate";

const fakeFetch = vi.fn().mockResolvedValue(
  new Response(JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    result: { content: [{ type: "text", text: "ok" }], isError: false },
  })),
);
const gw = new Gateway("http://gw.test", { fetch: fakeFetch });
```

For higher fidelity, run the gateway in a container (`ghcr.io/netgnarus/intentgate-gateway:latest`) and point the SDK at it.

## Companion repositories

| Repo | What |
| --- | --- |
| [intentgate-gateway](https://github.com/NetGnarus/intentgate-gateway) | The Go gateway this SDK talks to |
| [intentgate-sdk-python](https://github.com/NetGnarus/intentgate-sdk-python) | Python equivalent (byte-compatible attenuation) |
| [intentgate-helm](https://github.com/NetGnarus/intentgate-helm) | Helm chart for cluster deployment |
| [intentgate-extractor](https://github.com/NetGnarus/intentgate-extractor) | Intent extractor service |

## Compatibility

| Gateway | SDK |
| --- | --- |
| `>= 1.1` (latest) | `0.1.x` (recommended) |
| `1.0.x` | `0.1.x` (works; no `/v1/admin/tenants` for tenant switcher use cases) |
| `< 0.9` | not supported (token v3 with signed tenant claim required) |

## Development

```sh
npm install
npm run typecheck
npm run lint
npm test
npm run build
```

Pre-publish runs all of the above; `npm run build` produces `dist/index.js` (ESM), `dist/index.cjs` (CommonJS), and `dist/index.d.ts` (types).

## Releasing

Maintainers: see [`RELEASING.md`](RELEASING.md) for the one-time npm trusted-publisher setup and the tag-to-publish workflow.

## License

Apache 2.0. See [LICENSE](LICENSE).
