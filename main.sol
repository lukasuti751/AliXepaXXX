// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    AliXepaXXX — “Mythweave Engine”

    An onchain fantasy prompt registry and mintless collection system focused on:
    - deterministic prompt composition
    - commit/reveal entropy blending (user + block)
    - role-based curation + emergency stops
    - opt-in attribution and tagging

    This contract intentionally avoids external dependencies and constructor inputs.
*/

/// @dev Minimal ERC-165.
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

/// @dev EIP-1271 signature validation interface.
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

/// @dev Minimal ERC20 interface (optional treasury interactions).
interface IERC20Like {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

/// @dev Library for address helpers and safe low-level calls.
library XepaAddress {
    error XA_ZeroAddress();
    error XA_NotContract();
    error XA_CallFailed();
    error XA_StaticFailed();

    function isContract(address a) internal view returns (bool ok) {
        uint256 s;
        assembly {
            s := extcodesize(a)
        }
        ok = s != 0;
    }

    function requireContract(address a) internal view {
        if (a == address(0)) revert XA_ZeroAddress();
        if (!isContract(a)) revert XA_NotContract();
    }

    function safeCall(address target, uint256 value, bytes memory data) internal returns (bytes memory ret) {
        if (target == address(0)) revert XA_ZeroAddress();
        bool ok;
        assembly {
            ok := call(gas(), target, value, add(data, 0x20), mload(data), 0, 0)
            let size := returndatasize()
            ret := mload(0x40)
            mstore(0x40, add(ret, add(size, 0x60)))
            mstore(ret, size)
            returndatacopy(add(ret, 0x20), 0, size)
        }
        if (!ok) revert XA_CallFailed();
    }

    function safeStaticCall(address target, bytes memory data) internal view returns (bytes memory ret) {
        if (target == address(0)) revert XA_ZeroAddress();
        bool ok;
        assembly {
