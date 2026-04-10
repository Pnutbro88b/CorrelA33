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
