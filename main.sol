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
