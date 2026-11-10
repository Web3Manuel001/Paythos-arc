# Paythos MCP server

stdio JSON-RPC 2.0 daemon (docs/ARCHITECTURE.md Module 4.3). Any MCP-capable
host (Claude Desktop, Cursor, Claude Code) mounts the four budgeted tools:
`get_agent_budget`, `dry_run_errand`, `settle_invoice`, `query_x402_resource`.

## Install (one JSON block, env vars only — no config code)

Paste the `mcpServers` block from [`paythos.mcp.json`](paythos.mcp.json) into
your host's MCP config, replace the `<…>` placeholders with your own values,
and restart the host.

| Variable | Required | Purpose |
| --- | --- | --- |
| `PAYTHOS_EPHEMERAL_KEY` | yes | agent signing key (env only — AGENTS.md rule 5) |
| `PAYTHOS_VAULT_ADDRESS` | yes | deployed vault the vouchers settle against |
| `PAYTHOS_AGENT_EPOCH` | offline yes | INV-6 delegation epoch (ignored when RPC is set) |
| `PAYTHOS_MERCHANTS` | recommended | comma-separated destination allowlist |
| `PAYTHOS_RPC_URL` | no | enables live `remainingAllowance` + epoch sync |
| `PAYTHOS_MCP_LEDGER` | no | path for the persisted spend-ledger snapshot |

The server fails closed (exit 2, stderr only) when a required env var is missing
or the agent has no live delegation epoch. Network: `eip155:5042002` (Arc
Testnet) by default; `PAYTHOS_NETWORK` overrides (mainnet stays fail-closed
until PROTOCOL-OPEN-Q1 resolves).

## Local development

```bash
cd sdk/typescript
PAYTHOS_EPHEMERAL_KEY=0x… PAYTHOS_VAULT_ADDRESS=0x… PAYTHOS_AGENT_EPOCH=1 \
  npm run mcp
```
