// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.28;

/**
 * @title VoucherTypes
 * @notice Canonical EIP-712 voucher schema. This file is the single source of
 * truth for the wire format defined in docs/PROTOCOL.md §1 — the SDK signer
 * and the vault MUST hash identical typed data or signatures will not verify.
 * @dev Domain constants live in the vault (OZ `EIP712(name:"Paythos Protocol",
 *      version:"2", chainId, verifyingContract)) so the chain and deployment
 *      address are bound at runtime. DO NOT fork this struct without freezing
 *      a new protocol version in `EIP712._name`/`_version`.
 */
library VoucherTypes {
    struct Voucher {
        address agentKey;
        address merchant;
        address token;
        uint256 cumulativeAmount; // monotonically increasing session total
        uint256 validUntil; // hard expiry, unix seconds (SECURITY.md INV-4)
        uint64 epoch; // delegation epoch the voucher was signed under (INV-6)
        bytes32 memo; // 32-byte structured intent/invoice hash
    }

    /// keccak256("Voucher(address agentKey,address merchant,address token,uint256 cumulativeAmount,uint256 validUntil,uint64 epoch,bytes32 memo)")
    bytes32 public constant VOUCHER_TYPEHASH = keccak256(
        "Voucher(address agentKey,address merchant,address token,uint256 cumulativeAmount,uint256 validUntil,uint64 epoch,bytes32 memo)"
    );

    /// @notice Protocol version frozen at "3" — v2 lacked the epoch binding and
    ///      allowed pre-reauthorization vouchers to replay (see SECURITY.md INV-6).
    string public constant PROTOCOL_VERSION = "3";

    function structHash(Voucher memory voucher) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                VOUCHER_TYPEHASH,
                voucher.agentKey,
                voucher.merchant,
                voucher.token,
                voucher.cumulativeAmount,
                voucher.validUntil,
                voucher.epoch,
                voucher.memo
            )
        );
    }
}
