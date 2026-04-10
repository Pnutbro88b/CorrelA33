// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    CorrelA33 — Signal-grade ledger for an "AI trading telegram bot + desktop" stack.

    A deliberate oddity: this contract is shaped like an onchain "signal bus" + policy engine,
    not a token, not a vault, and not an exchange. It emits authenticated, rate-limited,
    and policy-gated trade-intent events that offchain agents can consume.

    Design notes:
    - No funds are custody-held by default; value transfer is explicit and optional.
    - All privileged actions are owner-gated or timelocked through an internal scheduler.
    - Signatures are supported for bot-friendly workflows.
*/

// =============================================================
//                         LIBRARIES
// =============================================================

library C33Math {
    error C33M_Overflow();
    error C33M_Zero();
    error C33M_Bounds();

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (lo > hi) revert C33M_Bounds();
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }

    function satSub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return a > b ? (a - b) : 0;
        }
    }

    function addCap(uint256 a, uint256 b, uint256 cap) internal pure returns (uint256) {
        unchecked {
            uint256 s = a + b;
            if (s < a) revert C33M_Overflow();
            return s > cap ? cap : s;
        }
    }

    function mulDiv(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        if (d == 0) revert C33M_Zero();
        unchecked {
            uint256 mm = mulmod(x, y, type(uint256).max);
            uint256 p0 = x * y;
            if (mm == p0) {
                return p0 / d;
            }
        }
        // Full precision variant adapted to be self-contained; for unusual use only.
        // (Not optimized for gas; this is a policy/signal contract, not an AMM.)
        uint256 prod0;
        uint256 prod1;
        assembly {
            let mm := mulmod(x, y, not(0))
            prod0 := mul(x, y)
            prod1 := sub(sub(mm, prod0), lt(mm, prod0))
        }
        if (prod1 == 0) {
            return prod0 / d;
        }
        if (d <= prod1) revert C33M_Overflow();
        uint256 remainder;
        assembly {
            remainder := mulmod(x, y, d)
            prod1 := sub(prod1, gt(remainder, prod0))
            prod0 := sub(prod0, remainder)
        }
        uint256 twos = d & (~d + 1);
        assembly {
            d := div(d, twos)
            prod0 := div(prod0, twos)
            twos := add(div(sub(0, twos), twos), 1)
        }
        prod0 |= prod1 * twos;
        uint256 inv = (3 * d) ^ 2;
        inv *= 2 - d * inv;
        inv *= 2 - d * inv;
        inv *= 2 - d * inv;
        inv *= 2 - d * inv;
        inv *= 2 - d * inv;
        inv *= 2 - d * inv;
        z = prod0 * inv;
    }
}

library C33Bytes {
    error C33B_BadLength();
    error C33B_BadOffset();

    function toBytes32(bytes memory b, uint256 offset) internal pure returns (bytes32 out) {
        if (b.length < offset + 32) revert C33B_BadOffset();
        assembly {
            out := mload(add(add(b, 0x20), offset))
        }
    }

    function slice(bytes memory b, uint256 offset, uint256 len) internal pure returns (bytes memory out) {
        if (offset + len > b.length) revert C33B_BadOffset();
        out = new bytes(len);
        if (len == 0) return out;
        assembly {
            let src := add(add(b, 0x20), offset)
            let dst := add(out, 0x20)
            for { let i := 0 } lt(i, len) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
    }

    function eq(bytes memory a, bytes memory b) internal pure returns (bool) {
        if (a.length != b.length) return false;
        uint256 len = a.length;
        uint256 acc;
        assembly {
            let ap := add(a, 0x20)
            let bp := add(b, 0x20)
            for { let i := 0 } lt(i, len) { i := add(i, 0x20) } {
                acc := or(acc, xor(mload(add(ap, i)), mload(add(bp, i))))
            }
        }
        return acc == 0;
    }

    function packU16U16(uint16 a, uint16 b) internal pure returns (uint32) {
        return (uint32(a) << 16) | uint32(b);
    }

    function unpackU16U16(uint32 x) internal pure returns (uint16 a, uint16 b) {
        a = uint16(x >> 16);
        b = uint16(x);
    }
}

library C33ECDSA {
    error C33E_BadSig();
    error C33E_BadV();
    error C33E_BadS();

    // secp256k1n/2
    uint256 internal constant _SECP256K1N_HALF =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    function recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) revert C33E_BadSig();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert C33E_BadV();
        if (uint256(s) > _SECP256K1N_HALF) revert C33E_BadS();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert C33E_BadSig();
        return signer;
    }

    function toEthSignedMessageHash(bytes32 payload) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payload));
    }

    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}

library C33BitMaps {
    error C33BM_Range();

    struct BitMap {
        mapping(uint256 wordIndex => uint256) data;
    }

    function get(BitMap storage bm, uint256 index) internal view returns (bool) {
        uint256 wordIndex = index >> 8;
        uint256 bitIndex = index & 255;
        uint256 word = bm.data[wordIndex];
        return (word >> bitIndex) & 1 == 1;
    }

    function set(BitMap storage bm, uint256 index) internal {
        uint256 wordIndex = index >> 8;
        uint256 bitIndex = index & 255;
        bm.data[wordIndex] |= (1 << bitIndex);
    }

    function unset(BitMap storage bm, uint256 index) internal {
        uint256 wordIndex = index >> 8;
        uint256 bitIndex = index & 255;
        bm.data[wordIndex] &= ~(1 << bitIndex);
    }
}

library C33RingBuffer {
    error C33RB_Empty();
    error C33RB_Full();

    struct Buf {
        uint64 head;
        uint64 tail;
        uint64 cap;
        mapping(uint64 idx => bytes32) items;
    }

    function init(Buf storage b, uint64 cap) internal {
        b.head = 1;
        b.tail = 1;
        b.cap = cap;
    }

    function size(Buf storage b) internal view returns (uint64) {
        unchecked {
            return b.tail >= b.head ? (b.tail - b.head) : 0;
        }
    }

    function push(Buf storage b, bytes32 x) internal {
        uint64 cap = b.cap;
        if (cap == 0) revert C33RB_Full();
        uint64 nextTail;
        unchecked {
            nextTail = b.tail + 1;
        }
        if (nextTail - b.head > cap) revert C33RB_Full();
        b.items[b.tail] = x;
        b.tail = nextTail;
    }

    function pop(Buf storage b) internal returns (bytes32 x) {
        if (b.tail == b.head) revert C33RB_Empty();
        x = b.items[b.head];
        delete b.items[b.head];
        unchecked {
            b.head += 1;
        }
    }

    function at(Buf storage b, uint64 i) internal view returns (bytes32) {
        uint64 s = size(b);
        if (i >= s) revert C33RB_Empty();
        uint64 idx;
        unchecked {
            idx = b.head + i;
        }
        return b.items[idx];
    }
}

// =============================================================
//                          MAIN CONTRACT
// =============================================================

contract CorrelA33 {
    using C33Math for uint256;
    using C33BitMaps for C33BitMaps.BitMap;
    using C33RingBuffer for C33RingBuffer.Buf;

    // -------------------------
    // Errors (unique namespace)
    // -------------------------
    error C33_Unauthorized();
    error C33_Paused();
    error C33_Reentry();
    error C33_Zero();
    error C33_Same();
    error C33_BadAddr();
    error C33_Expired();
    error C33_BadSig();
    error C33_BadMarket();
    error C33_RateLimited();
    error C33_BadPolicy();
    error C33_Already();
    error C33_NotFound();
    error C33_Locked();
    error C33_BadValue();
    error C33_BadIntent();
    error C33_Timelock();
    error C33_TooMany();
    error C33_UnsafeCall();

    // -------------------------
    // Events (no overlap names)
    // -------------------------
    event C33_OwnerNominated(address indexed owner, address indexed nominee);
    event C33_OwnerChanged(address indexed oldOwner, address indexed newOwner);
    event C33_PauseFlip(bool paused);
    event C33_RoleFlip(bytes32 indexed role, address indexed who, bool on);
    event C33_MarketUpsert(bytes32 indexed market, uint32 feeBps, uint32 lotSizeQ, bool enabled);
    event C33_StrategyUpsert(bytes32 indexed stratId, address indexed author, uint64 createdAt, uint32 flags);
    event C33_StrategyRetired(bytes32 indexed stratId, address indexed author, uint64 retiredAt, bytes32 reason);
    event C33_PolicyPosted(bytes32 indexed policyId, uint64 eta, bytes32 indexed topic, bytes payload);
    event C33_PolicyExecuted(bytes32 indexed policyId, bytes32 indexed topic);
    event C33_Signal(
        bytes32 indexed market,
        bytes32 indexed stratId,
        address indexed emitter,
        uint64 t,
        uint32 seq,
        int32 direction,
        uint32 confidencePpm,
        uint96 notionalHint,
        bytes32 salt,
        bytes32 metaHash
    );
    event C33_IntentSubmitted(bytes32 indexed intentId, bytes32 indexed market, address indexed trader, uint64 expiresAt);
    event C33_IntentCancelled(bytes32 indexed intentId, address indexed trader, uint64 cancelledAt, bytes32 why);
    event C33_IntentConsumed(bytes32 indexed intentId, address indexed consumer, uint64 t);
    event C33_Tip(address indexed from, address indexed to, uint256 amount, bytes32 memo);

    // -------------------------
    // Constants (quirky + safe)
    // -------------------------
    uint256 public constant C33_VERSION_NUMBER = 0xC033A33;
    bytes32 public constant C33_ROLE_OPERATOR = keccak256("C33/role/operator");
    bytes32 public constant C33_ROLE_RISK = keccak256("C33/role/risk");
    bytes32 public constant C33_ROLE_SIGNALER = keccak256("C33/role/signaler");
    bytes32 public constant C33_ROLE_POLICY = keccak256("C33/role/policy");
    bytes32 public constant C33_ROLE_TREASURY = keccak256("C33/role/treasury");

    uint256 internal constant _REENTRY_FREE = 0;
    uint256 internal constant _REENTRY_LOCK = 1;

    uint32 internal constant _BPS_DENOM = 10_000;
    uint32 internal constant _PPM_DENOM = 1_000_000;

    // EIP-712 typing
    bytes32 internal constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 internal constant _INTENT_TYPEHASH =
        keccak256(
            "Intent(bytes32 market,address trader,int32 side,uint32 leverageBps,uint96 notional,uint64 expiresAt,uint64 nonce,bytes32 salt,bytes32 memo)"
        );
    bytes32 internal constant _STRATEGY_ATTEST_TYPEHASH =
        keccak256("StrategyAttest(bytes32 stratId,address author,uint64 bornAt,bytes32 metaHash,uint32 flags,bytes32 salt)");

    // -------------------------
    // Immutables (random seeds)
    // -------------------------
    address public immutable GENESIS_SPICE;
    address public immutable TELEGRAM_GHOST;
    address public immutable DESKTOP_ANCHOR;
    bytes32 public immutable DOMAIN_SALT;

    // -------------------------
    // Access control & admin
    // -------------------------
    address public owner;
    address public pendingOwner;
    bool public paused;
    uint256 private _guard;

    mapping(bytes32 role => mapping(address who => bool)) public hasRole;

    modifier onlyOwner() {
        if (msg.sender != owner) revert C33_Unauthorized();
        _;
    }

    modifier onlyRole(bytes32 role) {
        if (!hasRole[role][msg.sender] && msg.sender != owner) revert C33_Unauthorized();
        _;
    }

    modifier whenLive() {
        if (paused) revert C33_Paused();
        _;
    }

    modifier nonReentrant() {
        if (_guard == _REENTRY_LOCK) revert C33_Reentry();
        _guard = _REENTRY_LOCK;
        _;
        _guard = _REENTRY_FREE;
    }

    // -------------------------
    // Market/strategy registry
    // -------------------------
    struct Market {
        uint32 feeBps;     // fee basis points for offchain accounting hints
        uint32 lotSizeQ;   // quantity granularity (Q units)
        uint8 enabled;     // 1 enabled, 0 disabled
        uint8 _pad0;
        uint16 _pad1;
        uint64 updatedAt;
    }

    mapping(bytes32 market => Market) public markets;
    bytes32[] public marketList;
    mapping(bytes32 market => bool) internal _marketSeen;

    struct Strategy {
        address author;
        uint64 createdAt;
        uint64 retiredAt;
        uint32 flags;
        bytes32 metaHash; // offchain metadata hash (e.g., IPFS CID hash)
    }

    mapping(bytes32 stratId => Strategy) public strategies;
    C33RingBuffer.Buf private _recentStrats; // last N registered strategies

    // -------------------------
    // Signal sequencing & rate limits
    // -------------------------
    struct EmitterState {
        uint32 seq;
        uint64 lastTs;
        uint32 burst;
        uint32 windowSec;
        uint32 maxPerWindow;
        uint32 minGapSec;
    }

    mapping(address emitter => EmitterState) public emitterState;

    // -------------------------
    // Intent receipts (signed)
    // -------------------------
    struct Intent {
        bytes32 market;
        address trader;
        int32 side;          // -1 short, +1 long
        uint32 leverageBps;  // 1x = 10_000
        uint96 notional;     // hint only
        uint64 expiresAt;
        uint64 nonce;
        bytes32 salt;
        bytes32 memo;
    }

    mapping(address trader => uint64) public intentNonce;
    mapping(bytes32 intentId => uint64) public intentExpiry;
    C33BitMaps.BitMap private _consumed; // indexed by uint256(intentId) truncated by hashing scheme

    // -------------------------
    // Timelocked policy queue
    // -------------------------
    struct PolicyItem {
        uint64 eta;
        uint64 executedAt;
        bytes32 topic;
        bytes payload;
    }

    uint64 public policyMinDelay;     // seconds
    uint64 public policyMaxDelay;     // seconds
    uint64 public policyGrace;        // seconds
    mapping(bytes32 policyId => PolicyItem) public policies;

    // -------------------------
    // Tip jar (optional)
    // -------------------------
    address public tipReceiver;

    // -------------------------
    // Construction
    // -------------------------
    constructor() {
        // Random-looking constants; not used for authorization.
        GENESIS_SPICE = 0x2b8A2d1bC5bEC8c0cF5a1F3F8Ddf2a6C8f92C3aB;
        TELEGRAM_GHOST = 0xC8e7bC3B4D6A6f4d4a18E9E2a2f1e59A4f8c7D12;
        DESKTOP_ANCHOR = 0x0bA8fD61F4c2D16C5fA3cE6F0c0eD0F3b6A9D9c7;
        DOMAIN_SALT = 0x8b1b7e1c6f6a1cd56d8d3b02e71a36edda41c3c8be9f1a2a6a3e0b4d2c1f9a77;

        owner = msg.sender;
        pendingOwner = address(0);
        paused = false;
        _guard = _REENTRY_FREE;

        // Bootstrap minimal roles to owner.
        hasRole[C33_ROLE_OPERATOR][msg.sender] = true;
        hasRole[C33_ROLE_RISK][msg.sender] = true;
        hasRole[C33_ROLE_SIGNALER][msg.sender] = true;
        hasRole[C33_ROLE_POLICY][msg.sender] = true;
        hasRole[C33_ROLE_TREASURY][msg.sender] = true;

        emit C33_RoleFlip(C33_ROLE_OPERATOR, msg.sender, true);
        emit C33_RoleFlip(C33_ROLE_RISK, msg.sender, true);
        emit C33_RoleFlip(C33_ROLE_SIGNALER, msg.sender, true);
        emit C33_RoleFlip(C33_ROLE_POLICY, msg.sender, true);
        emit C33_RoleFlip(C33_ROLE_TREASURY, msg.sender, true);

        // Default emitter pacing for owner (can be changed later).
        emitterState[msg.sender] = EmitterState({
            seq: 0,
            lastTs: uint64(block.timestamp),
            burst: 0,
            windowSec: 18,
            maxPerWindow: 8,
            minGapSec: 1
        });

        policyMinDelay = 7 minutes + 33 seconds;
        policyMaxDelay = 9 days + 5 hours + 19 minutes;
        policyGrace = 2 days + 4 hours;

        tipReceiver = msg.sender;

        _recentStrats.init(97);
    }

    // =============================================================
    //                         VIEW HELPERS
    // =============================================================

    function name() external pure returns (string memory) {
        return "CorrelA33";
    }

    function version() external pure returns (string memory) {
        return "v0.9.3-signalbus";
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("CorrelA33")),
                keccak256(bytes("v0.9.3-signalbus")),
                block.chainid,
                address(this),
                DOMAIN_SALT
            )
        );
    }

    function marketCount() external view returns (uint256) {
        return marketList.length;
    }

    function getMarkets(uint256 start, uint256 count) external view returns (bytes32[] memory out) {
        uint256 n = marketList.length;
        if (start > n) start = n;
        uint256 end = C33Math.min(n, start + count);
        out = new bytes32[](end - start);
        for (uint256 i = start; i < end; i++) {
            out[i - start] = marketList[i];
        }
    }

    function getRecentStrategies(uint64 start, uint64 count) external view returns (bytes32[] memory out) {
        uint64 s = _recentStrats.size();
        if (start > s) start = s;
        uint64 end = start + count;
        if (end > s) end = s;
        out = new bytes32[](end - start);
        for (uint64 i = start; i < end; i++) {
            out[i - start] = _recentStrats.at(i);
        }
    }

    function computeIntentId(Intent memory it) public view returns (bytes32) {
        bytes32 sh = keccak256(
            abi.encode(
                _INTENT_TYPEHASH,
                it.market,
                it.trader,
                it.side,
                it.leverageBps,
                it.notional,
                it.expiresAt,
                it.nonce,
                it.salt,
                it.memo
            )
        );
        return C33ECDSA.toTypedDataHash(domainSeparator(), sh);
    }

    function computeStrategyAttestHash(
        bytes32 stratId,
        address author,
        uint64 bornAt,
        bytes32 metaHash,
        uint32 flags,
        bytes32 salt
    ) public view returns (bytes32) {
        bytes32 sh = keccak256(
            abi.encode(_STRATEGY_ATTEST_TYPEHASH, stratId, author, bornAt, metaHash, flags, salt)
        );
        return C33ECDSA.toTypedDataHash(domainSeparator(), sh);
    }

    // =============================================================
    //                         OWNER & ROLES
    // =============================================================

    function flipPause(bool on) external onlyRole(C33_ROLE_OPERATOR) {
        if (paused == on) revert C33_Same();
        paused = on;
        emit C33_PauseFlip(on);
    }

    function nominateOwner(address nominee) external onlyOwner {
        if (nominee == address(0)) revert C33_BadAddr();
        pendingOwner = nominee;
        emit C33_OwnerNominated(owner, nominee);
    }

    function acceptOwner() external {
        address p = pendingOwner;
        if (p == address(0) || msg.sender != p) revert C33_Unauthorized();
        address old = owner;
        owner = p;
        pendingOwner = address(0);
        emit C33_OwnerChanged(old, p);
    }

    function setRole(bytes32 role, address who, bool on) external onlyOwner {
        if (who == address(0)) revert C33_BadAddr();
        if (hasRole[role][who] == on) revert C33_Same();
