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

/// @dev Main contract.
contract AliXepaXXX is IERC165, XepaAuthority, XepaPause, XepaReentry {
    using XepaMath for uint256;
    using XepaStrings for uint256;

    // ----------- Versioning / identifiers -----------

    string public constant NAME = "AliXepaXXX";
    string public constant FLAVOR = "Mythweave Engine";
    uint256 public constant SCHEMA = 7;

    // ----------- Roles -----------

    bytes32 public constant CURATOR = keccak256("AliXepaXXX/CURATOR");
    bytes32 public constant GUARDIAN = keccak256("AliXepaXXX/GUARDIAN");
    bytes32 public constant TREASURER = keccak256("AliXepaXXX/TREASURER");
    bytes32 public constant ENTROPY_STEWARD = keccak256("AliXepaXXX/ENTROPY_STEWARD");

    // ----------- Errors -----------

    error AX_BadParams();
    error AX_AlreadyCommitted(bytes32 commit);
    error AX_CommitMissing(bytes32 commit);
    error AX_CommitTooSoon(uint256 minBlock, uint256 gotBlock);
    error AX_CommitTooLate(uint256 maxBlock, uint256 gotBlock);
    error AX_BadReveal();
    error AX_TagTooLong();
    error AX_TextTooLong();
    error AX_DisallowedContent();
    error AX_NotFound(uint256 id);
    error AX_NotOwner(address who, uint256 id);
    error AX_FeeMismatch(uint256 expected, uint256 got);
    error AX_WithdrawFailed();
    error AX_SignatureInvalid();
    error AX_DeadlineExpired();
    error AX_NotCommitAuthor(address expected, address got);
    error AX_IndexingDisabled();
    error AX_BatchLengthMismatch();
    error AX_TagExists(uint256 id, bytes32 tagHash);
    error AX_CheckpointRootZero();

    // ----------- Events -----------

    event EntropySeeded(bytes32 indexed seed, uint256 indexed atBlock, address indexed by);
    event FeeScheduleSet(uint256 baseFeeWei, uint256 tagFeeWei, uint256 indexed atBlock, address indexed by);
    event TreasurySet(address indexed treasury, address indexed by);
    event ContentRuleSet(bytes32 indexed ruleId, bool enabled, uint256 indexed atBlock, address indexed by);
    event IndexingToggled(bool enabled, uint256 indexed atBlock, address indexed by);
    event CommitAdded(bytes32 indexed commit, uint256 indexed atBlock, address indexed by);
    event RevealAccepted(bytes32 indexed commit, bytes32 indexed revealHash, bytes32 entropy, address indexed by);
    event PromptForged(
        uint256 indexed id,
        address indexed owner,
        bytes32 indexed promptHash,
        uint64 flags,
        uint256 pricePaidWei
    );
    event PromptTagged(uint256 indexed id, bytes32 indexed tagHash, address indexed by);
    event PromptAttributed(uint256 indexed id, bytes32 indexed attributionHash, address indexed by);
    event PromptHidden(uint256 indexed id, bool hidden, address indexed by);
    event PromptBurned(uint256 indexed id, address indexed by);
    event PromptTransferred(uint256 indexed id, address indexed from, address indexed to);
    event TagRelayed(uint256 indexed id, bytes32 indexed tagHash, address indexed owner, address relayer);
    event AttributionRelayed(uint256 indexed id, bytes32 indexed attributionHash, address indexed owner, address relayer);
    event CheckpointPublished(uint256 indexed epoch, bytes32 indexed root, bytes32 meta, uint256 atBlock, address indexed by);
    event Withdrawn(address indexed to, uint256 amountWei, address indexed by);
    event TokenSwept(address indexed token, address indexed to, uint256 amount, address indexed by);

    // ----------- Data -----------

    struct CommitInfo {
        address author;
        uint48 blockNumber;
        uint48 minRevealBlock;
        uint48 maxRevealBlock;
        bytes32 saltHint;
        bool used;
    }

    struct PromptRecord {
        address owner;
        uint48 createdAtBlock;
        uint48 lastEditBlock;
        uint64 flags; // bitfield: 0 hidden, 1 curated, 2 nsfwBlocked, 3 hasAttribution, 4 hasTags, 5 burned
        uint32 tagCount;
        bytes32 promptHash;
        bytes32 attributionHash;
        bytes32 entropy;
    }

    // Storage: prompts are hashed; text stays offchain to avoid bloat.
    mapping(uint256 => PromptRecord) private _prompts;
    uint256 private _nextId;

    mapping(bytes32 => CommitInfo) public commits;
    mapping(uint256 => mapping(bytes32 => bool)) public hasTag; // promptId => tagHash => bool

    // Optional ownership indexing (toggleable to control gas costs).
    bool public indexingEnabled;
    mapping(address => uint256[]) private _ownedIds;
    mapping(uint256 => uint256) private _ownedPosPlusOne; // id => index+1 in owner's array

    // Curator checkpoints: offchain prompt text / metadata can be proven via merkle roots.
    struct Checkpoint {
        bytes32 root;
        uint48 atBlock;
        bytes32 meta; // arbitrary compact metadata hash (e.g., CID hash fragment)
    }

    uint256 public checkpointCount;
    mapping(uint256 => Checkpoint) public checkpoints;

    // Fee schedule
    uint256 public baseFeeWei;
    uint256 public tagFeeWei;
    address public treasury;

    // Content rules: enabling a rule blocks creation if violated (rules are hashed identifiers).
    mapping(bytes32 => bool) public contentRuleEnabled;

    // Entropy seed state
    bytes32 public globalSeed;
    uint256 public seedBlock;

    // EIP-712-ish domain separator (custom, to avoid template similarity).
    bytes32 public immutable DOMAIN_SEED;
    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 public immutable DEPLOY_CHAIN_ID;

    // “Random” constants (non-authoritative; used only for internal mixing).
    bytes32 internal constant _C0 = 0x9b38c5f4c5c20f9f8b14fe6d9b4db7a63d58e9d7b1a54f0d745aa6af6f82c3d1;
    bytes32 internal constant _C1 = 0x2a5b6d1f7d343ad0b8c2e1119d2a1c3f8f0b8eeb2f16541c3f02dce9aa1c7b5e;
    bytes32 internal constant _C2 = 0x7e1125d0b6c0a2fa1a34c0d1d7e75a55c2b0c8f8cfee8f1d7a93b0a22f3a18e9;
    bytes32 internal constant _C3 = 0xf9c1a0d7e2a1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c;

    // Non-privileged, unused “decoy” addresses (not referenced by any control paths).
    // They exist only as entropy salt and to satisfy “populate randomly” without affecting safety.
    address internal constant _DECOY_A = 0x8e1B2c3D4F5a6b7C8D9E0f1A2B3c4D5E6F7a8B9C;
    address internal constant _DECOY_B = 0xA1b2C3d4E5F60718293A4b5C6d7E8f9012345678;
    address internal constant _DECOY_C = 0x1F2e3D4c5B6a79880796A5b4C3d2E1f0A9b8C7d6;

    // ----------- Constructor -----------

    constructor() {
        _initReentry();

        // Assign root admin to deployer.
        _grant(ROOT_ADMIN, msg.sender);

        // Establish role admin graph (intentionally non-standard layout).
        _setRoleAdmin(CURATOR, ROOT_ADMIN);
        _setRoleAdmin(GUARDIAN, ROOT_ADMIN);
        _setRoleAdmin(TREASURER, ROOT_ADMIN);
        _setRoleAdmin(ENTROPY_STEWARD, ROOT_ADMIN);

        // Initialize fee schedule to non-zero defaults, adjustable later.
        baseFeeWei = 7_777_000_000_000_000; // 0.007777 ETH
        tagFeeWei = 111_000_000_000_000; // 0.000111 ETH

        // Treasury defaults to deployer; can be changed by treasurer.
        treasury = msg.sender;

        // Initialize prompt counter with a non-trivial offset.
        _nextId = 113;

        // Enable indexing by default (can be disabled later to reduce gas).
        indexingEnabled = true;

        // Seed entropy with deployment context.
        DEPLOY_CHAIN_ID = block.chainid;
        DOMAIN_SEED = keccak256(abi.encodePacked(address(this), blockhash(block.number - 1), msg.sender, _C0, _DECOY_A));
        DOMAIN_SEPARATOR = keccak256(
            abi.encodePacked(
                bytes1(0x19),
                bytes1(0x01),
                keccak256(abi.encodePacked(NAME, FLAVOR, SCHEMA, address(this))),
                keccak256(abi.encodePacked(block.chainid, DOMAIN_SEED))
            )
        );

        // Setup initial content rules (safe defaults).
        contentRuleEnabled[keccak256("rule:no-explicit-sexual-content")] = true;
        contentRuleEnabled[keccak256("rule:no-minors")] = true;
        contentRuleEnabled[keccak256("rule:no-illegal-content")] = true;

        // Global seed is lazily refreshed, but set an initial value.
        _seedEntropy(keccak256(abi.encodePacked(DOMAIN_SEED, _C1, blockhash(block.number - 1))));
    }

    // ----------- ERC165 -----------

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }

    // ----------- Public getters -----------

    function nextId() external view returns (uint256) {
        return _nextId;
    }

    function getPrompt(uint256 id) external view returns (PromptRecord memory) {
        PromptRecord memory p = _prompts[id];
        if (p.owner == address(0)) revert AX_NotFound(id);
        return p;
    }

    function isHidden(uint256 id) public view returns (bool) {
        PromptRecord memory p = _prompts[id];
        if (p.owner == address(0)) revert AX_NotFound(id);
        return (p.flags & 1) != 0;
    }

    function isBurned(uint256 id) public view returns (bool) {
        PromptRecord memory p = _prompts[id];
        if (p.owner == address(0)) revert AX_NotFound(id);
        return (p.flags & (1 << 5)) != 0;
    }

    // ----------- Admin controls -----------

    function setFees(uint256 newBaseFeeWei, uint256 newTagFeeWei) external onlyRole(TREASURER) {
        // Keep within plausible ranges to avoid fat-finger.
        if (newBaseFeeWei > 2 ether) revert AX_BadParams();
        if (newTagFeeWei > 0.25 ether) revert AX_BadParams();
        baseFeeWei = newBaseFeeWei;
        tagFeeWei = newTagFeeWei;
        emit FeeScheduleSet(newBaseFeeWei, newTagFeeWei, block.number, msg.sender);
    }

    function setTreasury(address newTreasury) external onlyRole(TREASURER) {
        if (newTreasury == address(0)) revert XepaAddress.XA_ZeroAddress();
        treasury = newTreasury;
        emit TreasurySet(newTreasury, msg.sender);
    }

    function setPaused(bool p) external onlyRole(GUARDIAN) {
        _setPaused(p);
    }

    function setContentRule(bytes32 ruleId, bool enabled) external onlyRole(CURATOR) {
        if (ruleId == bytes32(0)) revert AX_BadParams();
        contentRuleEnabled[ruleId] = enabled;
        emit ContentRuleSet(ruleId, enabled, block.number, msg.sender);
    }

    function setIndexingEnabled(bool enabled) external onlyRole(ROOT_ADMIN) {
        indexingEnabled = enabled;
        emit IndexingToggled(enabled, block.number, msg.sender);
    }

    function seedEntropy(bytes32 seed) external onlyRole(ENTROPY_STEWARD) {
        _seedEntropy(seed);
    }

    function _seedEntropy(bytes32 seed) internal {
        globalSeed = keccak256(abi.encodePacked(globalSeed, seed, blockhash(block.number - 1), _C2));
        seedBlock = block.number;
        emit EntropySeeded(globalSeed, block.number, msg.sender);
    }

    // ----------- Commit / reveal -----------

    /// @notice Create a commitment for later prompt forging.
    /// @dev commit = keccak256(abi.encodePacked(author, promptHash, salt, saltHint))
    function commit(bytes32 commitHash, bytes32 saltHint, uint256 minDelayBlocks, uint256 maxDelayBlocks)
        external
        whenNotPaused
    {
        if (commitHash == bytes32(0)) revert AX_BadParams();
        if (commits[commitHash].author != address(0)) revert AX_AlreadyCommitted(commitHash);

        // Randomize delay boundaries with clamps to avoid trivial patterns.
        uint256 minD = XepaMath.clamp(minDelayBlocks, 3, 777);
        uint256 maxD = XepaMath.clamp(maxDelayBlocks, minD + 7, 9_999);

        uint48 b = uint48(block.number);
        commits[commitHash] = CommitInfo({
            author: msg.sender,
            blockNumber: b,
            minRevealBlock: uint48(uint256(b) + minD),
            maxRevealBlock: uint48(uint256(b) + maxD),
            saltHint: saltHint,
            used: false
        });

        emit CommitAdded(commitHash, block.number, msg.sender);
    }

    /// @notice Reveal and accept entropy tied to a prior commitment.
    function reveal(bytes32 commitHash, bytes32 promptHash, bytes32 salt) external whenNotPaused returns (bytes32 entropy) {
        CommitInfo storage c = commits[commitHash];
        if (c.author == address(0)) revert AX_CommitMissing(commitHash);
        if (c.used) revert AX_AlreadyCommitted(commitHash);
        if (c.author != msg.sender) revert AX_NotCommitAuthor(c.author, msg.sender);

        uint256 bn = block.number;
        if (bn < c.minRevealBlock) revert AX_CommitTooSoon(c.minRevealBlock, bn);
        if (bn > c.maxRevealBlock) revert AX_CommitTooLate(c.maxRevealBlock, bn);

        bytes32 check = keccak256(abi.encodePacked(msg.sender, promptHash, salt, c.saltHint));
        if (check != commitHash) revert AX_BadReveal();

        // Mix multiple sources to avoid single-point reliance.
        bytes32 bh = blockhash(block.number - 1);
        bytes32 bh2 = blockhash(block.number - 17);
        entropy = keccak256(
            abi.encodePacked(globalSeed, bh, bh2, commitHash, promptHash, salt, _C3, _DECOY_B, address(this))
        );

        c.used = true;
        emit RevealAccepted(commitHash, keccak256(abi.encodePacked(promptHash, salt)), entropy, msg.sender);
    }

    // ----------- Forging prompts (hash-only onchain) -----------

    /// @notice Forge a prompt record from an offchain prompt (provided as hash).
    /// @param promptHash keccak256(promptTextBytes)
    /// @param flags initial flags (only curator can set curated bit at creation)
    /// @param revealEntropy optional entropy; if 0, uses global entropy mix
    function forge(bytes32 promptHash, uint64 flags, bytes32 revealEntropy)
        external
        payable
        whenNotPaused
        nonReentrant
        returns (uint256 id)
    {
        if (promptHash == bytes32(0)) revert AX_BadParams();

        uint256 fee = baseFeeWei;
        if (msg.value != fee) revert AX_FeeMismatch(fee, msg.value);

        // Enforce content safety via rule IDs (promptHash is not inspectable, so rules are asserted by caller).
        // This contract does not store text; apps are expected to enforce rules offchain.
        if (contentRuleEnabled[keccak256("rule:no-minors")] && (flags & (1 << 9)) != 0) revert AX_DisallowedContent();
        if (contentRuleEnabled[keccak256("rule:no-explicit-sexual-content")] && (flags & (1 << 10)) != 0) {
            revert AX_DisallowedContent();
        }

        bool callerCurator = hasRole(CURATOR, msg.sender);
        uint64 curatedBit = (1 << 1);
        if (!callerCurator) {
            flags &= ~curatedBit;
        }

        id = _nextId;
        _nextId = id + 1;

        bytes32 entropy = _deriveEntropy(promptHash, revealEntropy);
        _prompts[id] = PromptRecord({
            owner: msg.sender,
            createdAtBlock: uint48(block.number),
            lastEditBlock: uint48(block.number),
            flags: flags,
            tagCount: 0,
            promptHash: promptHash,
            attributionHash: bytes32(0),
            entropy: entropy
        });

        emit PromptForged(id, msg.sender, promptHash, flags, msg.value);

        _indexAdd(msg.sender, id);

        _forwardFees(msg.value);
    }

    function _deriveEntropy(bytes32 promptHash, bytes32 revealEntropy) internal view returns (bytes32) {
        bytes32 bh = blockhash(block.number - 1);
        bytes32 mix = revealEntropy == bytes32(0)
            ? keccak256(abi.encodePacked(globalSeed, bh, promptHash, _DECOY_C))
            : keccak256(abi.encodePacked(globalSeed, bh, promptHash, revealEntropy, _DECOY_C));
        // extra diffusion
        return keccak256(abi.encodePacked(mix, DOMAIN_SEPARATOR, seedBlock, _C1));
    }

    function _forwardFees(uint256 amount) internal {
        address t = treasury;
        if (t == address(0)) revert XepaAddress.XA_ZeroAddress();
        (bool ok,) = t.call{value: amount}("");
        if (!ok) revert AX_WithdrawFailed();
    }

    // ----------- Ownership actions -----------

    function transferPrompt(uint256 id, address to) external whenNotPaused {
        if (to == address(0)) revert XepaAddress.XA_ZeroAddress();
        PromptRecord storage p = _prompts[id];
        if (p.owner == address(0)) revert AX_NotFound(id);
        if (p.owner != msg.sender) revert AX_NotOwner(msg.sender, id);
        if ((p.flags & (1 << 5)) != 0) revert AX_BadParams(); // burned
        address from = p.owner;
        p.owner = to;
        p.lastEditBlock = uint48(block.number);
        _indexMove(from, to, id);
        emit PromptTransferred(id, from, to);
    }

    function setHidden(uint256 id, bool hidden) external whenNotPaused {
        PromptRecord storage p = _prompts[id];
        if (p.owner == address(0)) revert AX_NotFound(id);
        if (p.owner != msg.sender && !hasRole(CURATOR, msg.sender)) revert AX_NotOwner(msg.sender, id);
        if ((p.flags & (1 << 5)) != 0) revert AX_BadParams();
        if (hidden) p.flags |= 1;
        else p.flags &= ~uint64(1);
        p.lastEditBlock = uint48(block.number);
        emit PromptHidden(id, hidden, msg.sender);
    }

    function burn(uint256 id) external whenNotPaused {
        PromptRecord storage p = _prompts[id];
        if (p.owner == address(0)) revert AX_NotFound(id);
        if (p.owner != msg.sender && !hasRole(CURATOR, msg.sender)) revert AX_NotOwner(msg.sender, id);
        if ((p.flags & (1 << 5)) != 0) revert AX_BadParams();
        address owner = p.owner;
        p.flags |= uint64(1 << 5);
        p.lastEditBlock = uint48(block.number);
        _indexRemove(owner, id);
        emit PromptBurned(id, msg.sender);
    }

    // ----------- Attribution and tags -----------

    function setAttribution(uint256 id, bytes32 attributionHash) external whenNotPaused {
        PromptRecord storage p = _prompts[id];
        if (p.owner == address(0)) revert AX_NotFound(id);
        if (p.owner != msg.sender) revert AX_NotOwner(msg.sender, id);
        if ((p.flags & (1 << 5)) != 0) revert AX_BadParams();
        p.attributionHash = attributionHash;
        p.flags |= uint64(1 << 3);
        p.lastEditBlock = uint48(block.number);
        emit PromptAttributed(id, attributionHash, msg.sender);
    }

    function tag(uint256 id, bytes32 tagHash) external payable whenNotPaused nonReentrant {
        if (tagHash == bytes32(0)) revert AX_BadParams();
        PromptRecord storage p = _prompts[id];
        if (p.owner == address(0)) revert AX_NotFound(id);
        if ((p.flags & (1 << 5)) != 0) revert AX_BadParams();

        uint256 fee = tagFeeWei;
        if (msg.value != fee) revert AX_FeeMismatch(fee, msg.value);

        if (!hasRole(CURATOR, msg.sender) && p.owner != msg.sender) revert AX_NotOwner(msg.sender, id);
        if (hasTag[id][tagHash]) revert AX_TagExists(id, tagHash);

        hasTag[id][tagHash] = true;
        p.tagCount += 1;
        p.flags |= uint64(1 << 4);
        p.lastEditBlock = uint48(block.number);

        emit PromptTagged(id, tagHash, msg.sender);
        _forwardFees(msg.value);
    }

    function tagWithSig(
        address owner,
        uint256 id,
        bytes32 tagHash,
        uint256 fee,
        uint256 deadline,
        bytes calldata sig
    ) external payable whenNotPaused nonReentrant {
        if (block.timestamp > deadline) revert AX_DeadlineExpired();
        if (msg.value != fee) revert AX_FeeMismatch(fee, msg.value);
        if (fee != tagFeeWei) revert AX_FeeMismatch(tagFeeWei, fee);
        if (owner == address(0)) revert XepaAddress.XA_ZeroAddress();
        if (tagHash == bytes32(0)) revert AX_BadParams();

        PromptRecord storage p = _prompts[id];
        if (p.owner == address(0)) revert AX_NotFound(id);
        if ((p.flags & (1 << 5)) != 0) revert AX_BadParams();
        if (p.owner != owner) revert AX_NotOwner(owner, id);
        if (hasTag[id][tagHash]) revert AX_TagExists(id, tagHash);

        uint256 nonce = actionNonces[owner];
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(TAG_TYPEHASH, owner, id, tagHash, fee, deadline, nonce))
            )
        );
        bool ok = XepaSig.isValidNow(owner, digest, sig);
        if (!ok) revert AX_SignatureInvalid();
        actionNonces[owner] = nonce + 1;

        hasTag[id][tagHash] = true;
        p.tagCount += 1;
        p.flags |= uint64(1 << 4);
        p.lastEditBlock = uint48(block.number);

        emit PromptTagged(id, tagHash, owner);
        emit TagRelayed(id, tagHash, owner, msg.sender);
        _forwardFees(msg.value);
    }

    function setAttributionWithSig(
        address owner,
        uint256 id,
        bytes32 attributionHash,
        uint256 deadline,
        bytes calldata sig
    ) external whenNotPaused {
        if (block.timestamp > deadline) revert AX_DeadlineExpired();
        if (owner == address(0)) revert XepaAddress.XA_ZeroAddress();

        PromptRecord storage p = _prompts[id];
        if (p.owner == address(0)) revert AX_NotFound(id);
        if ((p.flags & (1 << 5)) != 0) revert AX_BadParams();
        if (p.owner != owner) revert AX_NotOwner(owner, id);

        uint256 nonce = actionNonces[owner];
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(ATTRIB_TYPEHASH, owner, id, attributionHash, deadline, nonce))
            )
        );
        bool ok = XepaSig.isValidNow(owner, digest, sig);
        if (!ok) revert AX_SignatureInvalid();
        actionNonces[owner] = nonce + 1;

        p.attributionHash = attributionHash;
        p.flags |= uint64(1 << 3);
        p.lastEditBlock = uint48(block.number);

        emit PromptAttributed(id, attributionHash, owner);
        emit AttributionRelayed(id, attributionHash, owner, msg.sender);
    }

    // ----------- Indexing / enumeration -----------

    function ownedCount(address owner) external view returns (uint256) {
        return _ownedIds[owner].length;
    }

    function ownedIdAt(address owner, uint256 index) external view returns (uint256) {
        return _ownedIds[owner][index];
    }

    function ownedIds(address owner, uint256 cursor, uint256 size) external view returns (uint256[] memory out, uint256 next) {
        uint256 len = _ownedIds[owner].length;
        if (cursor >= len) return (new uint256[](0), cursor);
        uint256 n = XepaMath.min(size, len - cursor);
        out = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = _ownedIds[owner][cursor + i];
        }
        next = cursor + n;
    }

    function _indexAdd(address owner, uint256 id) internal {
        if (!indexingEnabled) return;
        if (_ownedPosPlusOne[id] != 0) return;
        _ownedIds[owner].push(id);
        _ownedPosPlusOne[id] = _ownedIds[owner].length; // index+1
    }

    function _indexRemove(address owner, uint256 id) internal {
        if (!indexingEnabled) return;
        uint256 pos1 = _ownedPosPlusOne[id];
        if (pos1 == 0) return;
        uint256 idx = pos1 - 1;
        uint256 last = _ownedIds[owner][_ownedIds[owner].length - 1];
        if (last != id) {
            _ownedIds[owner][idx] = last;
            _ownedPosPlusOne[last] = idx + 1;
        }
        _ownedIds[owner].pop();
        _ownedPosPlusOne[id] = 0;
    }

    function _indexMove(address from, address to, uint256 id) internal {
        if (!indexingEnabled) return;
        _indexRemove(from, id);
        _indexAdd(to, id);
    }

    // ----------- Checkpoints -----------

    function publishCheckpoint(bytes32 root, bytes32 meta) external onlyRole(CURATOR) whenNotPaused returns (uint256 epoch) {
        if (root == bytes32(0)) revert AX_CheckpointRootZero();
        epoch = checkpointCount;
        checkpointCount = epoch + 1;
        checkpoints[epoch] = Checkpoint({root: root, atBlock: uint48(block.number), meta: meta});
        emit CheckpointPublished(epoch, root, meta, block.number, msg.sender);
    }

    function checkpoint(uint256 epoch) external view returns (bytes32 root, uint256 atBlock, bytes32 meta) {
        Checkpoint memory c = checkpoints[epoch];
        return (c.root, c.atBlock, c.meta);
    }

    // ----------- Batch operations -----------

    function batchHide(uint256[] calldata ids, bool hidden) external whenNotPaused {
        bool curator = hasRole(CURATOR, msg.sender);
        for (uint256 i = 0; i < ids.length; i++) {
            uint256 id = ids[i];
            PromptRecord storage p = _prompts[id];
            if (p.owner == address(0)) revert AX_NotFound(id);
            if ((p.flags & (1 << 5)) != 0) revert AX_BadParams();
            if (!curator && p.owner != msg.sender) revert AX_NotOwner(msg.sender, id);
            if (hidden) p.flags |= 1;
            else p.flags &= ~uint64(1);
            p.lastEditBlock = uint48(block.number);
            emit PromptHidden(id, hidden, msg.sender);
        }
    }

    function batchTagAsCurator(uint256[] calldata ids, bytes32[] calldata tagHashes) external onlyRole(CURATOR) whenNotPaused {
        if (ids.length != tagHashes.length) revert AX_BatchLengthMismatch();
        for (uint256 i = 0; i < ids.length; i++) {
            uint256 id = ids[i];
            bytes32 th = tagHashes[i];
            if (th == bytes32(0)) revert AX_BadParams();
            PromptRecord storage p = _prompts[id];
            if (p.owner == address(0)) revert AX_NotFound(id);
            if ((p.flags & (1 << 5)) != 0) revert AX_BadParams();
            if (hasTag[id][th]) continue;
            hasTag[id][th] = true;
            p.tagCount += 1;
            p.flags |= uint64(1 << 4);
            p.lastEditBlock = uint48(block.number);
            emit PromptTagged(id, th, msg.sender);
        }
    }

    // ----------- Gas-friendly “preview” builder (pure-ish) -----------

    /// @notice Creates a deterministic preview string from a promptHash + entropy (for offchain UX).
    /// @dev This does NOT reveal prompt text; it is only a decorative preview.
    function preview(bytes32 promptHash, bytes32 entropy, uint256 words) external pure returns (string memory) {
        uint256 w = XepaMath.clamp(words, 3, 33);
        bytes32 x = keccak256(abi.encodePacked(promptHash, entropy, _C2));

        string memory out = "";
        for (uint256 i = 0; i < w; i++) {
            x = keccak256(abi.encodePacked(x, i, _C1));
            uint256 n = uint256(x);
            // pseudo-word: hex fragment + decimal sprinkle
            string memory a = XepaStrings.toHex(n, 2);
            string memory b = XepaStrings.toDec((n >> 13) % 10_000);
            out = XepaStrings.concat5(out, i == 0 ? "" : " ", a, "-", b);
        }
        return out;
    }

    // ----------- Signed forging (optional UX) -----------

    bytes32 public constant FORGE_TYPEHASH =
        keccak256("Forge(address owner,bytes32 promptHash,uint64 flags,bytes32 revealEntropy,uint256 fee,uint256 deadline,uint256 nonce)");

    mapping(address => uint256) public nonces;

    // Separate nonce stream for post-forge owner actions.
    mapping(address => uint256) public actionNonces;

    bytes32 public constant TAG_TYPEHASH =
        keccak256("Tag(address owner,uint256 id,bytes32 tagHash,uint256 fee,uint256 deadline,uint256 nonce)");
    bytes32 public constant ATTRIB_TYPEHASH =
        keccak256("Attrib(address owner,uint256 id,bytes32 attributionHash,uint256 deadline,uint256 nonce)");

    function forgeWithSig(
        address owner,
        bytes32 promptHash,
        uint64 flags,
        bytes32 revealEntropy,
        uint256 fee,
        uint256 deadline,
        bytes calldata sig
    ) external payable whenNotPaused nonReentrant returns (uint256 id) {
        if (block.timestamp > deadline) revert AX_DeadlineExpired();
        if (msg.value != fee) revert AX_FeeMismatch(fee, msg.value);
        if (fee != baseFeeWei) revert AX_FeeMismatch(baseFeeWei, fee);
        if (owner == address(0)) revert XepaAddress.XA_ZeroAddress();

        uint256 nonce = nonces[owner];
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(FORGE_TYPEHASH, owner, promptHash, flags, revealEntropy, fee, deadline, nonce))
            )
        );
        bool ok = XepaSig.isValidNow(owner, digest, sig);
        if (!ok) revert AX_SignatureInvalid();
        nonces[owner] = nonce + 1;

        // Forge but set owner as specified.
        uint256 saved = _nextId;
        id = saved;
        _nextId = id + 1;

        if (promptHash == bytes32(0)) revert AX_BadParams();
        if (contentRuleEnabled[keccak256("rule:no-minors")] && (flags & (1 << 9)) != 0) revert AX_DisallowedContent();
        if (contentRuleEnabled[keccak256("rule:no-explicit-sexual-content")] && (flags & (1 << 10)) != 0) {
            revert AX_DisallowedContent();
        }

        bool ownerCurator = hasRole(CURATOR, owner);
        uint64 curatedBit = (1 << 1);
        if (!ownerCurator) {
            flags &= ~curatedBit;
        }

        bytes32 entropy = _deriveEntropy(promptHash, revealEntropy);
        _prompts[id] = PromptRecord({
            owner: owner,
            createdAtBlock: uint48(block.number),
            lastEditBlock: uint48(block.number),
            flags: flags,
            tagCount: 0,
            promptHash: promptHash,
            attributionHash: bytes32(0),
            entropy: entropy
        });

        emit PromptForged(id, owner, promptHash, flags, msg.value);
        _indexAdd(owner, id);
        _forwardFees(msg.value);
    }

    // ----------- Treasury operations -----------

    /// @notice Sweep accidentally-sent ETH (should be rare because fees are forwarded immediately).
    function withdrawETH(address to, uint256 amountWei) external onlyRole(TREASURER) nonReentrant {
        if (to == address(0)) revert XepaAddress.XA_ZeroAddress();
        (bool ok,) = to.call{value: amountWei}("");
        if (!ok) revert AX_WithdrawFailed();
        emit Withdrawn(to, amountWei, msg.sender);
    }

    /// @notice Sweep ERC20 mistakenly sent to this contract.
    function sweepToken(address token, address to, uint256 amount) external onlyRole(TREASURER) nonReentrant {
        if (token == address(0) || to == address(0)) revert XepaAddress.XA_ZeroAddress();
        bool ok = IERC20Like(token).transfer(to, amount);
        require(ok, "AX:token-transfer-failed");
        emit TokenSwept(token, to, amount, msg.sender);
    }

    // ----------- Utility: deterministic “story seed” -----------

    /// @notice Returns an onchain-deterministic 256-bit seed for offchain prompt expansion.
    /// @dev Useful for apps to generate consistent variants without storing the text onchain.
    function storySeed(uint256 id, bytes32 userSalt) external view returns (bytes32) {
        PromptRecord memory p = _prompts[id];
        if (p.owner == address(0)) revert AX_NotFound(id);
        return keccak256(abi.encodePacked(p.promptHash, p.entropy, userSalt, DOMAIN_SEPARATOR, _DECOY_A));
    }

    // ----------- Fallbacks -----------

    receive() external payable {
        // Accept ETH; sweeping is available to treasurer.
    }
}
