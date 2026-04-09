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
            ok := staticcall(gas(), target, add(data, 0x20), mload(data), 0, 0)
            let size := returndatasize()
            ret := mload(0x40)
            mstore(0x40, add(ret, add(size, 0x60)))
            mstore(ret, size)
            returndatacopy(add(ret, 0x20), 0, size)
        }
        if (!ok) revert XA_StaticFailed();
    }
}

/// @dev Small math helpers with explicit error surface.
library XepaMath {
    error XM_Div0();
    error XM_Range();

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (lo > hi) revert XM_Range();
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }

    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) revert XM_Div0();
        unchecked {
            return a == 0 ? 0 : ((a - 1) / b) + 1;
        }
    }

    function satSub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return a > b ? a - b : 0;
        }
    }

    function absDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a - b : b - a;
    }
}

/// @dev Bytes and packing helpers.
library XepaBytes {
    error XB_OOB();

    function slice(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        if (start + len > b.length) revert XB_OOB();
        out = new bytes(len);
        assembly {
            let src := add(add(b, 0x20), start)
            let dst := add(out, 0x20)
            for { let i := 0 } lt(i, len) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
    }

    function toBytes32(bytes memory b, uint256 start) internal pure returns (bytes32 out) {
        if (start + 32 > b.length) revert XB_OOB();
        assembly {
            out := mload(add(add(b, 0x20), start))
        }
    }

    function toUint256(bytes memory b, uint256 start) internal pure returns (uint256 out) {
        out = uint256(toBytes32(b, start));
    }

    function equal(bytes32 a, bytes32 c) internal pure returns (bool) {
        return a == c;
    }
}

/// @dev String tools tuned for compact metadata.
library XepaStrings {
    bytes16 private constant _HEX = 0x30313233343536373839616263646566;

    function toHex(uint256 x, uint256 lenBytes) internal pure returns (string memory) {
        uint256 len = lenBytes * 2;
        bytes memory out = new bytes(2 + len);
        out[0] = "0";
        out[1] = "x";
        for (uint256 i = 0; i < len; i++) {
            uint8 v = uint8(x >> ((len - 1 - i) * 4)) & 0x0f;
            out[2 + i] = bytes1(_HEX[v]);
        }
        return string(out);
    }

    function toDec(uint256 x) internal pure returns (string memory) {
        if (x == 0) return "0";
        uint256 y = x;
        uint256 digits;
        while (y != 0) {
            digits++;
            y /= 10;
        }
        bytes memory out = new bytes(digits);
        while (x != 0) {
            digits -= 1;
            out[digits] = bytes1(uint8(48 + (x % 10)));
            x /= 10;
        }
        return string(out);
    }

    function concat3(string memory a, string memory b, string memory c) internal pure returns (string memory) {
        return string(abi.encodePacked(a, b, c));
    }

    function concat5(string memory a, string memory b, string memory c, string memory d, string memory e)
        internal
        pure
        returns (string memory)
    {
        return string(abi.encodePacked(a, b, c, d, e));
    }
}

/// @dev Signature verifier supporting EOAs and EIP-1271.
library XepaSig {
    using XepaAddress for address;

    error XS_BadSig();
    error XS_Expired();
    error XS_BadV();

    bytes4 internal constant _EIP1271_MAGIC = 0x1626ba7e;

    function recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert XS_BadSig();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v != 27 && v != 28) revert XS_BadV();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert XS_BadSig();
        return signer;
    }

    function isValidNow(address signer, bytes32 digest, bytes calldata sig) internal view returns (bool) {
        if (!XepaAddress.isContract(signer)) {
            return recover(digest, sig) == signer;
        }
        bytes memory ret = XepaAddress.safeStaticCall(
            signer, abi.encodeWithSelector(IERC1271.isValidSignature.selector, digest, sig)
        );
        if (ret.length < 4) return false;
        bytes4 mv = bytes4(XepaBytes.toBytes32(ret, 0));
        return mv == _EIP1271_MAGIC;
    }
}

/// @dev Role-based access control, intentionally not identical to common templates.
abstract contract XepaAuthority {
    error XA_Unauthorized(address caller, bytes32 role);
    error XA_RoleZero();
    error XA_AdminZero();
    error XA_RoleAlready(bytes32 role, address who);
    error XA_RoleMissing(bytes32 role, address who);

    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed prevAdminRole, bytes32 indexed newAdminRole);
    event RoleGranted(bytes32 indexed role, address indexed who, address indexed by);
    event RoleRevoked(bytes32 indexed role, address indexed who, address indexed by);

    mapping(bytes32 => mapping(address => bool)) private _hasRole;
    mapping(bytes32 => bytes32) private _adminOf;

    bytes32 public constant ROOT_ADMIN = keccak256("AliXepaXXX/ROOT_ADMIN");

    modifier onlyRole(bytes32 role) {
        if (!_hasRole[role][msg.sender]) revert XA_Unauthorized(msg.sender, role);
        _;
    }

    function hasRole(bytes32 role, address who) public view returns (bool) {
        return _hasRole[role][who];
    }

    function roleAdmin(bytes32 role) public view returns (bytes32) {
        bytes32 a = _adminOf[role];
        return a == bytes32(0) ? ROOT_ADMIN : a;
    }

    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal {
        if (role == bytes32(0)) revert XA_RoleZero();
        if (adminRole == bytes32(0)) revert XA_AdminZero();
        bytes32 prev = roleAdmin(role);
        _adminOf[role] = adminRole;
        emit RoleAdminChanged(role, prev, adminRole);
    }

    function grantRole(bytes32 role, address who) external onlyRole(roleAdmin(role)) {
        _grant(role, who);
    }

    function revokeRole(bytes32 role, address who) external onlyRole(roleAdmin(role)) {
        _revoke(role, who);
    }

    function renounceRole(bytes32 role) external {
        _revoke(role, msg.sender);
    }

    function _grant(bytes32 role, address who) internal {
        if (role == bytes32(0)) revert XA_RoleZero();
        if (who == address(0)) revert XepaAddress.XA_ZeroAddress();
        if (_hasRole[role][who]) revert XA_RoleAlready(role, who);
        _hasRole[role][who] = true;
        emit RoleGranted(role, who, msg.sender);
    }

    function _revoke(bytes32 role, address who) internal {
        if (role == bytes32(0)) revert XA_RoleZero();
        if (who == address(0)) revert XepaAddress.XA_ZeroAddress();
        if (!_hasRole[role][who]) revert XA_RoleMissing(role, who);
        _hasRole[role][who] = false;
        emit RoleRevoked(role, who, msg.sender);
    }
}

/// @dev Minimal pausability with explicit semantics.
abstract contract XepaPause {
    error XP_Paused();
    error XP_NotPaused();

    event PauseToggled(bool paused, address indexed by);

    bool private _paused;

    modifier whenNotPaused() {
        if (_paused) revert XP_Paused();
        _;
    }

    modifier whenPaused() {
        if (!_paused) revert XP_NotPaused();
        _;
    }

    function paused() public view returns (bool) {
        return _paused;
    }

    function _setPaused(bool p) internal {
        _paused = p;
        emit PauseToggled(p, msg.sender);
    }
}

/// @dev Reentrancy guard with custom layout.
abstract contract XepaReentry {
    error XR_Reentered();

    uint256 private _gate;

    modifier nonReentrant() {
        if (_gate == 2) revert XR_Reentered();
        _gate = 2;
        _;
        _gate = 1;
    }

    function _initReentry() internal {
        _gate = 1;
    }
}
