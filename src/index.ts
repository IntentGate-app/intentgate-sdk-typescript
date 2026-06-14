/**
 * @intentgate-app/intentgate — TypeScript SDK for the IntentGate gateway.
 *
 * The intent of this package is the "three lines of agent code"
 * promise from the IntentGate pitch:
 *
 * @example
 * ```ts
 * import { Gateway } from "@intentgate-app/intentgate";
 *
 * const gw = new Gateway("http://localhost:8080", {
 *   token: process.env.INTENTGATE_TOKEN,
 * });
 * const result = await gw.toolCall("read_invoice", {
 *   arguments: { id: "123" },
 *   intentPrompt: "Process today's AP invoices",
 * });
 * ```
 *
 * `toolCall` throws a typed error when the gateway blocks; the error
 * carries which check fired and why. See {@link IntentGateError} and
 * its subclasses for the full hierarchy.
 *
 * Capability attenuation lives in {@link attenuate}: derive a strictly
 * more restrictive child token from a parent without ever touching
 * the gateway's master key.
 */

export {
  Gateway,
  type ContentBlock,
  type GatewayOptions,
  type IntentGateMetadata,
  type ToolCallOptions,
  type ToolCallResult,
} from "./client.js";

export {
  attenuate,
  decodeToken,
  AttenuationError,
  CaveatType,
  type AttenuateOptions,
  type Caveat,
} from "./capability.js";

export {
  BudgetError,
  CapabilityError,
  GatewayError,
  IntentError,
  IntentGateError,
  PolicyError,
  ProtocolError,
  ProvenanceError,
  forCode,
} from "./errors.js";

export {
  MemoryStore,
  MemoryProvenanceError,
  SESSION_KEY_SIZE,
  ZERO_HASH,
  canonical,
  deriveSessionKey,
  sign,
  verify,
  verifyChain,
  type Envelope,
  type MemoryReadHook,
  type MemoryWriteHook,
} from "./memory.js";
