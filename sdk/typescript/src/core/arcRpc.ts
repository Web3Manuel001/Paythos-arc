/**
 * Arc RPC transport hardening.
 *
 * Why this module exists (found during the live grant demo, 2026-11):
 *
 * 1. `new JsonRpcProvider(url)` probes `eth_chainId` on startup over Node's
 *    `http`/`https`. That connect is dual-stack, so it can race an unreachable
 *    IPv6 route (ENETUNREACH) against an IPv4 connect that times out, and the
 *    whole provider dies with `AggregateError [ETIMEDOUT]` before the first
 *    RPC call. Pinning the Arc network at construction (`staticNetwork`) skips
 *    the probe entirely and `<network>.getNetwork()` stays a pure cache read.
 *    Separately, Node's default 250 ms per-address connect budget cancels
 *    healthy Cloudflare sockets (see CONNECT_ATTEMPT_TIMEOUT_MS below).
 * 2. Ethers does not retry ordinary provider calls, so one transient TCP
 *    timeout aborts a funded run halfway through. The `fetch` (undici)
 *    transport below carries a bounded per-attempt timeout plus a short retry
 *    ladder for connection-level failures.
 * 3. Ethers logs its network-detection retries with `console.log`. In the MCP
 *    stdio server stdout IS the JSON-RPC channel, so that line corrupts the
 *    frame. `installArcRpcTransport()` never writes to stdout, and the MCP
 *    server routes `console.log` to stderr (see `src/mcp/server.ts`).
 *
 * Fail closed: a network whose chain ID is still UNVERIFIED (mainnet,
 * PROTOCOL-OPEN-Q1) refuses to build a provider.
 */
import { setDefaultResultOrder } from "node:dns";
import { setDefaultAutoSelectFamilyAttemptTimeout } from "node:net";
import {
  FetchRequest,
  JsonRpcProvider,
  Network,
  type GetUrlResponse,
} from "ethers";
import { CHAIN_REGISTRY, type PaythosNetwork } from "../types.js";

const DEFAULT_NETWORK: PaythosNetwork = "eip155:5042002";
const DEFAULT_TIMEOUT_MS = 20_000;
const DEFAULT_ATTEMPTS = 3;
const RETRY_BASE_MS = 400;

/**
 * Node 20+ connects to every resolved address in parallel and gives each one
 * `autoSelectFamilyAttemptTimeout` before moving on; the default is 250 ms.
 * Arc's RPC sits behind Cloudflare and our IPv4 connects regularly take 300 ms
 * to 4 s, so the default cancelled healthy sockets and surfaced as
 * `AggregateError [ETIMEDOUT]` while `curl` to the same addresses succeeded in
 * 200-500 ms. Two seconds keeps real connects alive and still falls through a
 * dead IPv6 route.
 */
const CONNECT_ATTEMPT_TIMEOUT_MS = 2_000;

/** Socket/fetch failures worth another attempt; everything else is final. */
const RETRYABLE_CODES = new Set([
  "ETIMEDOUT",
  "ECONNRESET",
  "ECONNREFUSED",
  "ENETUNREACH",
  "EHOSTUNREACH",
  "ENOTFOUND",
  "EAI_AGAIN",
  "EPIPE",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_SOCKET",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_BODY_TIMEOUT",
]);

export interface ArcRpcOptions {
  /** Network to pin on the provider. Defaults to Arc Testnet. */
  network?: PaythosNetwork;
  /** Per-attempt HTTP timeout in milliseconds. Defaults to 20s. */
  timeoutMs?: number;
  /** Attempts per JSON-RPC request (including the first). Defaults to 3. */
  attempts?: number;
}

let installed = false;
let attemptsConfigured = DEFAULT_ATTEMPTS;

/**
 * Install the process-wide ethers transport: IPv4-first DNS, `fetch` instead of
 * `node:http`, bounded timeouts and retries. Idempotent; the first call wins
 * for the retry budget. Safe to call from any entry point (SDK script, MCP bin).
 */
export function installArcRpcTransport(options: ArcRpcOptions = {}): void {
  // Prefer IPv4: the demo host has an IPv6 route that answers ENETUNREACH.
  try {
    setDefaultResultOrder("ipv4first");
  } catch {
    // Node < 17 has no dual-stack ordering knob; the retry ladder still applies.
  }
  // Give each address a realistic budget instead of Node 24's 250 ms default.
  try {
    setDefaultAutoSelectFamilyAttemptTimeout(CONNECT_ATTEMPT_TIMEOUT_MS);
  } catch {
    // Older Node lacks the knob; per-request timeouts and retries still apply.
  }
  if (installed) return;
  installed = true;
  attemptsConfigured = Math.max(1, Math.trunc(options.attempts ?? DEFAULT_ATTEMPTS));
  FetchRequest.registerGetUrl((request) => fetchWithRetry(request, attemptsConfigured));
}

/**
 * Build a JsonRpcProvider pinned to an Arc network.
 *
 * The chain ID is taken from `CHAIN_REGISTRY`, never from the RPC's answer, so a
 * hostile or misconfigured endpoint cannot talk the SDK onto another chain.
 * Callers that want a liveness proof should still issue one real request
 * (`eth_chainId`) and compare it, as `scripts/arc-mcp-live.ts` does.
 */
export function arcRpcProvider(rpcUrl: string, options: ArcRpcOptions = {}): JsonRpcProvider {
  const network = options.network ?? DEFAULT_NETWORK;
  const entry = CHAIN_REGISTRY[network];
  if (entry.chainId === null || !entry.verified) {
    throw new Error(
      `FAIL CLOSED: ${network} chain ID is unverified (PROTOCOL-OPEN-Q1); refusing to build a provider`,
    );
  }
  installArcRpcTransport(options);
  const request = new FetchRequest(rpcUrl);
  request.timeout = Math.max(1, Math.trunc(options.timeoutMs ?? DEFAULT_TIMEOUT_MS));
  return new JsonRpcProvider(
    request,
    Network.from({ chainId: entry.chainId, name: `arc-${entry.chainId}` }),
    // staticNetwork: no detectNetwork probe, no ethers console.log on startup.
    { staticNetwork: true, batchMaxCount: 1 },
  );
}

async function fetchWithRetry(request: FetchRequest, attempts: number): Promise<GetUrlResponse> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    if (attempt > 1) await sleep(RETRY_BASE_MS * 2 ** (attempt - 2));
    try {
      return await fetchOnce(request);
    } catch (error) {
      lastError = error;
      if (!isRetryable(error)) break;
    }
  }
  throw lastError;
}

async function fetchOnce(request: FetchRequest): Promise<GetUrlResponse> {
  const init: RequestInit = {
    method: request.method,
    headers: request.headers,
    redirect: "follow",
    signal: AbortSignal.timeout(request.timeout),
    ...(request.hasBody() ? { body: Buffer.from(request.body) } : {}),
  };
  const response = await fetch(request.url, init);
  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key] = value;
  });
  return {
    statusCode: response.status,
    statusMessage: response.statusText,
    headers,
    // undici already decodes content-encoding; ethers never gunzips this path.
    body: new Uint8Array(await response.arrayBuffer()),
  };
}

function isRetryable(error: unknown): boolean {
  const code = errorCode(error);
  if (code && RETRYABLE_CODES.has(code)) return true;
  // Timeouts raised by AbortSignal.timeout() and undici's own abort path.
  return error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError");
}

function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const direct = (error as { code?: unknown }).code;
  if (typeof direct === "string") return direct;
  const cause = (error as { cause?: unknown }).cause;
  if (typeof cause === "object" && cause !== null) {
    const code = (cause as { code?: unknown }).code;
    if (typeof code === "string") return code;
  }
  return undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
