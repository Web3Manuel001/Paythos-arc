// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

/**
 * @title VaultErrors
 * @notice Every revert reason in the vault. Custom errors (selector-safe) instead
 *      of strings so gas and debugging stay deterministic. Invariant identifiers
 *      reference docs/SECURITY.md §1.
 */
library VaultErrors {
    /// Signature does not verify against the vault's EIP-712 domain (INV-1 gate).
    error InvalidSignature();
    /// `block.timestamp > voucher.validUntil` (INV-4 Temporal Expiry).
    error SessionExpired();
    /// agentKey has no active delegation, or was revoked by the owner.
    error UnauthorizedAgent();
    /// Destination merchant is not authorized for this agent key.
    error UnauthorizedMerchant();
    /// `cumulativeAmount <= previouslyClaimed` — replay/stale voucher (INV-1).
    error InvalidVoucherAmount();
    /// Voucher delta exceeds this delegation's single-tx ceiling (INV-3).
    error MaxPerTxExceeded();
    /// `voucher.epoch ≠ agent.epoch` — voucher predates the current delegation
    ///      (INV-6 Delegation Epoch Binding; SECURITY.md).
    error SessionEpochMismatch();
    /// Rolling 24h ceiling would be breached (INV-2 Daily Ceiling).
    error DailyLimitExceeded();
    /// `memoHash` argument disagrees with `voucher.memo`.
    error MemoMismatch();
    /// Voucher references a token other than the vault's immutable settlement token.
    error TokenMismatch();
    /// Deploy/config supplied a zero address where only a real address is safe.
    error ZeroAddress();
    /// Set-at-construction immutables mutated (treasury, token).
    error ImmutableConfigured();
    /// Fee update pushed `feeBps` above the protocol cap (docs/PROTOCOL.md §2.8).
    error FeeCapExceeded(uint256 attempted, uint256 capInBps);
    /// `claimVoucher` reached while the vault has no delegated unsettled float.
    error NothingToClaim();
    /// Token operations would corrupt the 1:1 capital isolation ratio (INV-5).
    error DepositUnsupported();
}
