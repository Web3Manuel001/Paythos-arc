// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {IPaythosVault} from "../interfaces/IPaythosVault.sol";
import {VoucherTypes} from "../types/VoucherTypes.sol";
import {PolicyTypes} from "../types/PolicyTypes.sol";
import {VaultErrors} from "../errors/VaultErrors.sol";
import {VaultEvents} from "../events/VaultEvents.sol";
import {RollingWindow} from "../libraries/RollingWindow.sol";
import {FeeDistribution} from "../libraries/FeeDistribution.sol";

/**
 * @title PaythosVault
 * @notice Sovereign USDC custody + bytecode policy enforcement + batch settlement
 *      anchor for the Paythos Protocol (docs/ARCHITECTURE.md Module 1).
 *
 * Non-negotiable invariants enforced here (docs/SECURITY.md §1):
 *   INV-1 Monotonic Claim      — cumulative vouchers strictly increase per pair.
 *   INV-2 Daily Ceiling        — rolling 24h window, no cron/oracle needed.
 *   INV-3 Atomic Per-Tx Bound  — delta ≤ policy.maxPerTx always.
 *   INV-4 Temporal Expiry      — vouchers valid only before `expiresAt`.
 *   INV-5 Non-Custodial Reserve— owner-only capital exits; no delegatecall anywhere.
 *
 * Deployment rule (AGENTS.md): the treasury is supplied at construction via the
 * deploy script (`PAYTHOS_TREASURY_ADDRESS`); a zero address reverts, fail closed.
 */
contract PaythosVault is IPaythosVault, EIP712, Ownable2Step, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using VoucherTypes for VoucherTypes.Voucher;

    /// @notice Token for settlement. Hard-set so vouchers cannot drift chains/tokens.
    IERC20 public immutable SETTLEMENT_TOKEN;
    /// @notice Protocol treasury; receives the take-rate on every claim.
    address public immutable TREASURY;

    /// @notice Current protocol fee in basis points (capped at 500 by FeeDistribution).
    uint256 private _feeBps = FeeDistribution.DEFAULT_FEE_BPS;

    struct AgentState {
        PolicyTypes.Policy policy;
        uint256 spentToday;
        uint256 windowStart;
        bool active;
        // Clean-slate epoch (docs/fixtures/DelegationLifecycle): each `authorizeAgent`
        // bumps this, orphaning every per-pair cumulative claim from prior windows.
        // We cannot loop-delete maps, so epoch scoping gives a deterministic reset.
        uint64 epoch;
    }

    struct PairClaim {
        uint64 epoch;
        uint256 cumulativeClaimed;
    }

    /// @notice agentKey => state (policy + rolling window).
    mapping(address agentKey => AgentState state) private _agents;
    /// @notice agentKey => epoch-scoped cumulative amount already settled per merchant (INV-1).
    mapping(address agentKey => mapping(address merchant => PairClaim claim)) private _claims;
    /// @notice agentKey => merchant destination allowlist (Module 4.5).
    mapping(address agentKey => mapping(address merchant => bool allowed)) private _allowedMerchants;

    modifier onlyActiveAgent(address agentKey) {
        if (!_agents[agentKey].active) revert VaultErrors.UnauthorizedAgent();
        _;
    }

    constructor(IERC20 settlementToken_, address treasury_) Ownable(msg.sender) EIP712("Paythos Protocol", "2") {
        if (address(settlementToken_) == address(0)) revert VaultErrors.ZeroAddress();
        if (treasury_ == address(0)) revert VaultErrors.ZeroAddress(); // fail closed
        SETTLEMENT_TOKEN = settlementToken_;
        TREASURY = treasury_;

        emit VaultEvents.FeeUpdated(0, _feeBps);
    }

    // ============================================================
    // Human capital layer (INV-5)
    // ============================================================

    /// @notice Deposit settlement-token reserve. Owner + designated treasurers.
    function deposit(uint256 amount) external onlyOwner {
        if (amount == 0) revert VaultErrors.NothingToClaim();
        SETTLEMENT_TOKEN.safeTransferFrom(msg.sender, address(this), amount);
        emit VaultEvents.VaultDeposit(msg.sender, address(SETTLEMENT_TOKEN), amount);
    }

    /// @notice Owner-only capital exit. There is no other drain (INV-5).
    function emergencyWithdraw() external onlyOwner {
        uint256 balance = SETTLEMENT_TOKEN.balanceOf(address(this));
        if (balance == 0) revert VaultErrors.NothingToClaim();
        SETTLEMENT_TOKEN.safeTransfer(msg.sender, balance);
        emit VaultEvents.EmergencyWithdrawal(msg.sender, address(SETTLEMENT_TOKEN), balance);
    }

    /// @notice Rescue stray tokens accidentally sent to the vault (airdrops etc.).
    function rescueToken(address token, address to, uint256 amount) external onlyOwner {
        if (token == address(SETTLEMENT_TOKEN)) revert VaultErrors.DepositUnsupported();
        SafeERC20.safeTransfer(IERC20(token), to, amount);
    }

    // ============================================================
    // Delegation lifecycle
    // ============================================================

    /// @notice Bind `agentKey` to `policy`. Authorizing an existing key resets
    ///      its rolling window and claims — clean-slate semantics (fail closed).
    function authorizeAgent(address agentKey, PolicyTypes.Policy calldata policy) external onlyOwner {
        if (agentKey == address(0)) revert VaultErrors.ZeroAddress();
        if (policy.expiresAt <= block.timestamp) revert VaultErrors.SessionExpired();
        if (policy.maxPerTx > policy.dailyLimit) revert VaultErrors.MaxPerTxExceeded();

        _agents[agentKey] = AgentState({
            policy: policy,
            spentToday: 0,
            windowStart: block.timestamp, // fresh window opens now
            active: true,
            epoch: _agents[agentKey].epoch + 1 // clean-slate: orphans stale pair claims
        });
        emit VaultEvents.AgentAuthorized(agentKey, policy.dailyLimit, policy.maxPerTx, policy.expiresAt);
    }

    /// @notice Owner kill-switch: instant on-chain revocation (INV-4 backstop).
    function revokeAgent(address agentKey) external onlyOwner {
        AgentState storage agent = _agents[agentKey];
        if (!agent.active) revert VaultErrors.UnauthorizedAgent();
        agent.active = false;
        emit VaultEvents.AgentRevoked(agentKey, msg.sender);
    }

    /// @notice Add a merchant address to an agent's destination allowlist.
    function allowMerchant(address agentKey, address merchant) external onlyOwner onlyActiveAgent(agentKey) {
        if (merchant == address(0)) revert VaultErrors.ZeroAddress();
        _allowedMerchants[agentKey][merchant] = true;
        emit VaultEvents.MerchantAllowed(agentKey, merchant);
    }

    /// @notice Remove a merchant from an agent's destination allowlist.
    function blockMerchant(address agentKey, address merchant) external onlyOwner {
        _allowedMerchants[agentKey][merchant] = false;
        emit VaultEvents.MerchantBlocked(agentKey, merchant);
    }

    // ============================================================
    // Merchant batch settlement (INV-1..INV-4, fee switch)
    // ============================================================

    /**
     * @notice Settle the monotonic delta of a single signed voucher.
     * @return deltaPaid The actual amount wired to `voucher.merchant` after fees.
     */
    function claimVoucher(VoucherTypes.Voucher calldata voucher, bytes calldata signature)
        external
        nonReentrant
        returns (uint256 deltaPaid)
    {
        AgentState storage agent = _agents[voucher.agentKey];

        // ---- Authorization liveness first (cheap, fail closed) ----
        if (!agent.active) revert VaultErrors.UnauthorizedAgent();

        // ---- INV-4: temporal expiry, and policy validity ----
        if (block.timestamp > voucher.validUntil) revert VaultErrors.SessionExpired();
        if (block.timestamp > agent.policy.expiresAt) revert VaultErrors.SessionExpired();

        // ---- Token binding: vouchers can never transcend the vault's own chain-token ----
        if (voucher.token != address(SETTLEMENT_TOKEN)) revert VaultErrors.TokenMismatch();

        // ---- INV-1: monotonic cumulative claim, epoch-scoped ----
        PairClaim storage priorClaim = _claims[voucher.agentKey][voucher.merchant];
        uint256 previousClaimed = (priorClaim.epoch == agent.epoch) ? priorClaim.cumulativeClaimed : 0;
        if (voucher.cumulativeAmount <= previousClaimed) revert VaultErrors.InvalidVoucherAmount();

        // ---- Destination allowlist (Module 4.5) ----
        if (!_allowedMerchants[voucher.agentKey][voucher.merchant]) {
            revert VaultErrors.UnauthorizedMerchant();
        }

        // ---- EIP-712 signature verification ----
        // The voucher SEALES over its own memo field; no separate memoHash arg
        // to desynchronize (memo mismatch security note in docs/PROTOCOL.md §2).
        bytes32 digest = _hashTypedDataV4(voucher.structHash());
        if (!SignatureChecker.isValidSignatureNow(voucher.agentKey, digest, signature)) {
            revert VaultErrors.InvalidSignature();
        }

        uint256 delta = voucher.cumulativeAmount - previousClaimed;

        // ---- INV-3: per-tx ceiling ----
        if (delta > agent.policy.maxPerTx) revert VaultErrors.MaxPerTxExceeded();

        // ---- INV-2: rolling 24h daily ceiling (dynamic, no cron) ----
        (uint256 spentToday_, uint256 windowStart_) =
            RollingWindow.applyRollover(block.timestamp, agent.spentToday, agent.windowStart, false);
        if (spentToday_ + delta > agent.policy.dailyLimit) revert VaultErrors.DailyLimitExceeded();

        // ---- Fee routing: deduct at source (docs/ARCHITECTURE.md Module 1.6) ----
        (uint256 fee, uint256 net) = FeeDistribution.split(delta, _feeBps);

        // ---- Effects before interactions ----
        agent.spentToday = spentToday_ + delta;
        agent.windowStart = windowStart_;
        priorClaim.epoch = agent.epoch;
        priorClaim.cumulativeClaimed = voucher.cumulativeAmount;

        emit VaultEvents.VoucherClaimed(
            voucher.agentKey, voucher.merchant, voucher.cumulativeAmount, delta, fee, voucher.memo
        );

        SETTLEMENT_TOKEN.safeTransfer(voucher.merchant, net);
        if (fee > 0) {
            SETTLEMENT_TOKEN.safeTransfer(TREASURY, fee);
        }

        return net;
    }

    // ============================================================
    // Protocol configuration
    // ============================================================

    function setFeeBps(uint256 newFeeBps) external onlyOwner {
        if (newFeeBps > FeeDistribution.FEE_CAP_BPS) {
            revert VaultErrors.FeeCapExceeded(newFeeBps, FeeDistribution.FEE_CAP_BPS);
        }
        emit VaultEvents.FeeUpdated(_feeBps, newFeeBps);
        _feeBps = newFeeBps;
    }

    // ============================================================
    // Telemetry (MCP `get_vault_budget`)
    // ============================================================

    /// @notice Exposed for off-chain SDK/test signing symmetry (docs/PROTOCOL.md §1.2).
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function isAgentActive(address agentKey) external view returns (bool) {
        return _agents[agentKey].active;
    }

    function getPolicy(address agentKey) external view returns (PolicyTypes.Policy memory) {
        return _agents[agentKey].policy;
    }

    function spentToday(address agentKey) external view returns (uint256) {
        if (!_agents[agentKey].active) return 0;
        return RollingWindow.current(block.timestamp, _agents[agentKey].spentToday, _agents[agentKey].windowStart);
    }

    function claimed(address agentKey, address merchant) external view returns (uint256) {
        PairClaim storage priorClaim = _claims[agentKey][merchant];
        if (priorClaim.epoch == _agents[agentKey].epoch) return priorClaim.cumulativeClaimed;
        return 0;
    }

    function remainingAllowance(address agentKey) external view returns (uint256) {
        AgentState storage agent = _agents[agentKey];
        if (!agent.active) return 0;
        return agent.policy.dailyLimit - RollingWindow.current(block.timestamp, agent.spentToday, agent.windowStart);
    }

    function feeBps() external view returns (uint256) {
        return _feeBps;
    }
}
