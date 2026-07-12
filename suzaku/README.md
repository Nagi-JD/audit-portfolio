# Suzaku — Intra-Epoch Validator Stake Inflation

**Severity:** 🔴 Critical
**Type:** Accounting desynchronization / cross-epoch state
**Status:** ✅ Confirmed & fixed (PR #251)
**Public reference:** https://github.com/suzaku-network/suzaku-core/issues/250

---

## Summary

An accounting discrepancy exists between **where completed stake increases are written** and **where used stake is read**. `completeValidatorWeightUpdate` writes the new stake into the **next** epoch's cache while releasing the operator's locks, but `getOperatorUsedStakeCached` reads only from the **current** epoch's cache.

Because the "used stake" an operator sees does not reflect the increase already committed for the next epoch, an operator can update multiple validators sequentially **within a single epoch** and inflate validator weight on the P-chain **beyond their actual collateral** — trending toward unbounded stake.

## Impact

- A single operator can push validator weight on the P-chain far above the collateral they actually locked.
- This breaks the core protocol invariant *used stake ≤ collateral*, corrupting the security accounting the network relies on for weight distribution.

## Root cause

| Function | Writes to | Reads from |
|---|---|---|
| `completeValidatorWeightUpdate` | **next** epoch cache | — |
| `getOperatorUsedStakeCached` | — | **current** epoch cache |

The write and the read target different epoch caches, so committed increases are invisible to the "available stake" check during the same epoch → phantom available stake.

## Recommended fix

Make `getOperatorUsedStakeCached` read the **maximum** of the current- and next-epoch stake caches per validator, so committed-but-not-yet-active increases are counted against available stake and the intra-epoch inflation window is closed. Addressed in **PR #251**.

## Notes

Originally reported via the project's disclosure channel and reproduced against the accounting paths; the maintainers confirmed and patched it.
