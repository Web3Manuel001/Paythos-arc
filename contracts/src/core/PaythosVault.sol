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
import {SlidingWindow} from "../libraries/SlidingWindow.sol";
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
        SlidingWindow.Window window; // exact sliding 24h spend buckets (INV-2)
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
    /// @notice Destination allowlist (Module 4.5). Value = the delegation epoch
    ///      in which the owner allowed the merchant; a re-authorization bumps
    ///      the epoch, so stale grants become invalid WITHOUT any sweep. This
    ///      removes the unbounded clear loop (and allow/block churn growth)
    ///      from `authorizeAgent` (reviewer 2026-11).
    mapping(address agentKey => mapping(address merchant => uint64 allowedEpoch)) private _allowedMerchants;

    modifier onlyActiveAgent(address agentKey) {
        if (!_agents[agentKey].active) revert VaultErrors.UnauthorizedAgent();
        _;
    }

    constructor(IERC20 settlementToken_, address treasury_)
        Ownable(msg.sender)
        EIP712("Paythos Protocol", VoucherTypes.PROTOCOL_VERSION)
    {
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
    ///      its rolling window, claims AND destination allowlist — clean-slate
    ///      semantics, fail closed (docs/fixtures/DelegationLifecycle).
    function authorizeAgent(address agentKey, PolicyTypes.Policy calldata policy) external onlyOwner {
        if (agentKey == address(0)) revert VaultErrors.ZeroAddress();
        if (policy.expiresAt <= block.timestamp) revert VaultErrors.SessionExpired();
        if (policy.maxPerTx > policy.dailyLimit) revert VaultErrors.MaxPerTxExceeded();

        // Allowlist grants are epoch-tagged, so the epoch bump below orphans
        // them with no storage sweep (bounds authorizeAgent gas regardless of
        // how many merchants were allowed/blocked before — reviewer 2026-11).
        SlidingWindow.Window memory freshWindow;
        _agents[agentKey] = AgentState({
            policy: policy,
            window: freshWindow, // all-zero buckets: fresh delegation opens empty
            active: true,
            epoch: _agents[agentKey].epoch + 1 // clean-slate: orphans stale pair claims + stale vouchers
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
    ///      The grant is tagged with the CURRENT delegation epoch: the next
    ///      `authorizeAgent` invalidates it without a sweep (INV-6 clean slate).
    function allowMerchant(address agentKey, address merchant) external onlyOwner onlyActiveAgent(agentKey) {
        if (merchant == address(0)) revert VaultErrors.ZeroAddress();
        _allowedMerchants[agentKey][merchant] = _agents[agentKey].epoch;
        emit VaultEvents.MerchantAllowed(agentKey, merchant);
    }

    /// @notice Remove a merchant from an agent's destination allowlist.
    function blockMerchant(address agentKey, address merchant) external onlyOwner {
        delete _allowedMerchants[agentKey][merchant];
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

        // ---- INV-6: the voucher was signed under the CURRENT delegation epoch;
        //      pre-reauthorization vouchers can never replay into fresh claims.
        if (voucher.epoch != agent.epoch) revert VaultErrors.SessionEpochMismatch();

        // ---- Token binding: vouchers can never transcend the vault's own chain-token ----
        if (voucher.token != address(SETTLEMENT_TOKEN)) revert VaultErrors.TokenMismatch();

        // ---- INV-1: monotonic cumulative claim, epoch-scoped ----
        PairClaim storage priorClaim = _claims[voucher.agentKey][voucher.merchant];
        uint256 previousClaimed = (priorClaim.epoch == agent.epoch) ? priorClaim.cumulativeClaimed : 0;
        if (voucher.cumulativeAmount <= previousClaimed) revert VaultErrors.InvalidVoucherAmount();

        // ---- Destination allowlist (Module 4.5) ----
        if (_allowedMerchants[voucher.agentKey][voucher.merchant] != agent.epoch) {
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

        // ---- INV-2: EXACT sliding 24h daily ceiling (hourly buckets, no cron) ----
        SlidingWindow.Window storage window = agent.window;
        uint64 hourIndex = uint64(block.timestamp / SlidingWindow.HOUR);
        if (SlidingWindow.spent(window, hourIndex) + delta > agent.policy.dailyLimit) {
            revert VaultErrors.DailyLimitExceeded();
        }

        // ---- Fee routing: deduct at source (docs/ARCHITECTURE.md Module 1.6) ----
        (uint256 fee, uint256 net) = FeeDistribution.split(delta, _feeBps);

        // ---- Effects before interactions ----
        SlidingWindow.add(window, hourIndex, delta);
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
        // A zero take-rate silently disables fee routing to treasury; keep a
        // 1 bp floor (reviewer 2026-11).
        if (newFeeBps < FeeDistribution.FEE_FLOOR_BPS) {
            revert VaultErrors.FeeFloorViolated(newFeeBps, FeeDistribution.FEE_FLOOR_BPS);
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
        AgentState storage agent = _agents[agentKey];
        if (!agent.active) return 0;
        return SlidingWindow.spent(agent.window, uint64(block.timestamp / SlidingWindow.HOUR));
    }

    /// @notice Current delegation epoch — agents MUST embed it into every voucher
    ///      (INV-6). Off-chain signers read it right after `authorizeAgent` and
    ///      after every re-authorization (clean-slate session rotation).
    function epochOf(address agentKey) external view returns (uint64) {
        return _agents[agentKey].epoch;
    }

    function claimed(address agentKey, address merchant) external view returns (uint256) {
        PairClaim storage priorClaim = _claims[agentKey][merchant];
        if (priorClaim.epoch == _agents[agentKey].epoch) return priorClaim.cumulativeClaimed;
        return 0;
    }

    function remainingAllowance(address agentKey) external view returns (uint256) {
        AgentState storage agent = _agents[agentKey];
        if (!agent.active) return 0;
        uint256 hourIndex = uint64(block.timestamp / SlidingWindow.HOUR);
        uint256 used = SlidingWindow.spent(agent.window, uint64(hourIndex));
        return used < agent.policy.dailyLimit ? agent.policy.dailyLimit - used : 0;
    }

    function feeBps() external view returns (uint256) {
        return _feeBps;
    }
}
