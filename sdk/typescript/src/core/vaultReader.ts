/**
 * On-chain vault telemetry (docs/ROADMAP.md Gate 2.5).
 * Read-only access to a deployed PaythosVault: config, policy, allowance and
 * settlement state. All reads go through a pluggable RawCaller so tests run
 * offline; the ethers-backed caller is the production adapter.
 */
import { Interface, type Provider } from "ethers";
import paythosVaultAbi from "../abi/paythosVault.json";

export interface RawCaller {
  call(to: string, data: string): Promise<string>;
}

export class EthersRawCaller implements RawCaller {
  constructor(
    readonly provider: Provider,
    readonly vaultAddress: string,
  ) {}

  async call(to: string, data: string): Promise<string> {
    return this.provider.call({ to, data });
  }
}

export interface VaultPolicyOnChain {
  dailyLimit: bigint;
  maxPerTx: bigint;
  /** Unix seconds; 0 = never expires per vault convention. */
  expiresAt: bigint;
}

export interface VaultTelemetry {
  settlementToken: string;
  treasury: string;
  feeBps: bigint;
}

export interface AgentTelemetry {
  active: boolean;
  policy: VaultPolicyOnChain;
  remainingAllowance: bigint;
}

const IFACE = new Interface(paythosVaultAbi as unknown as []);

export class VaultReader {
  constructor(
    protected readonly caller: RawCaller,
    readonly vaultAddress: string,
  ) {}

  /** Vault-wide config: settlement token, treasury, protocol fee (bps). */
  async telemetry(): Promise<VaultTelemetry> {
    const [token, treasury, feeBps] = await Promise.all([
      this.#call("SETTLEMENT_TOKEN", [], (r) => addr(r[0])),
      this.#call("TREASURY", [], (r) => addr(r[0])),
      this.#call("feeBps", [], (r) => r[0] as bigint),
    ]);
    return { settlementToken: token, treasury, feeBps };
  }

  async isAgentActive(agentKey: string): Promise<boolean> {
    return this.#call("isAgentActive", [agentKey], (r) => r[0] as boolean);
  }

  /**
   * Live delegation epoch (INV-6): signers MUST embed this in every voucher;
   * call it after `authorizeAgent` and after every re-authorization.
   */
  async epochOf(agentKey: string): Promise<number> {
    const epoch = await this.#call("epochOf", [agentKey], (r) => r[0] as bigint);
    return Number(epoch);
  }

  /** Unexpired Remaining allowance in the rolling 24h window (INV-2). */
  async remainingAllowance(agentKey: string): Promise<bigint> {
    return this.#call("remainingAllowance", [agentKey], (r) => r[0] as bigint);
  }

  async policyOf(agentKey: string): Promise<VaultPolicyOnChain> {
    const tuple = await this.#call("getPolicy", [agentKey], (res) => res[0]);
    const t = tuple as { dailyLimit: bigint; maxPerTx: bigint; expiresAt: bigint };
    return { dailyLimit: t.dailyLimit, maxPerTx: t.maxPerTx, expiresAt: t.expiresAt };
  }

  /** Cumulative amount already settled for (agent, merchant) on-chain. */
  async claimedFor(agentKey: string, merchant: string): Promise<bigint> {
    return this.#call("claimed", [agentKey, merchant], (r) => r[0] as bigint);
  }

  async #call<T>(fn: string, args: unknown[], project: (result: unknown[]) => T): Promise<T> {
    const data = IFACE.encodeFunctionData(fn, args as never[]);
    const raw = await this.caller.call(this.vaultAddress, data);
    const decoded = IFACE.decodeFunctionResult(fn, raw) as unknown[];
    return project(decoded);
  }
}

function addr(v: unknown): string {
  return (v as string).toLowerCase();
}

/** Convenience: an ethers-backed VaultReader in one call. */
export function vaultReaderFor(provider: Provider, vaultAddress: string): VaultReader {
  return new VaultReader(new EthersRawCaller(provider, vaultAddress), vaultAddress);
}
