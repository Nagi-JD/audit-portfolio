# AladdinDAO — f(x) Protocol v2 Security Audit

**Date:** 2026-04-28
**Auditor:** Saturn
**Target:** [`AladdinDAO/fx-protocol-contracts`](https://github.com/AladdinDAO/fx-protocol-contracts) @ `5e198e9` (main)
**Scope:** Unaudited delta since `1e8a491` — limit-order mechanics, short-pool infrastructure, new periphery facets, recent `FxUSDRegeneracy` fixes.
**Method:** Manual, line-by-line trace through value-flow paths.

---

## Findings

| ID | Severity | Area | Summary |
|----|----------|------|---------|
| **H-1** | 🟠 High | `LimitOrderManager` | Wrong-value validator + missing post-action reconciliation lets the treasury capture a maker's **surplus collateral** during partial fills of stale close orders. |
| **M-1** | 🟡 Medium | `LibRouter` | Same-token conversion early-return returns the **full balance instead of the delta**, leaking pre-existing diamond dust to the caller. |
| **M-2** | 🟡 Medium | `PositionOperateFacet` | Missing collateral sweep in `borrowFromLong` amplifies M-1 by leaving converter overpayments unrefunded. |
| **L-1** | 🔵 Low | `LimitOrderManager` | Redundant arithmetic (`takingAmount × makingAmount ÷ takingAmount`) reduces to a no-op; functionally inert. |
| **L-2** | 🔵 Low | `ShortPool` | Swapped variable destructure in index update yields a correct boolean but a **wrong shortfall value** for future consumers. |
| **L-3** | 🔵 Low | Flash-loan facets | Implicit zero-fee assumption; **non-zero pool fees brick** flash-loan settlement paths. |
| **L-4** | 🔵 Low | `ShortPool` | Funding accrual **underflow** when `rate × duration ≥ 100%` permanently bricks pool updates. |

## H-1 in one paragraph

When a stale close order is partially filled, the validator checks the wrong value and no post-action reconciliation runs. The maker's surplus collateral — value that should return to the maker after settling the position — is instead routed to the protocol treasury. It's a real loss of maker funds (to the treasury, not to the tx submitter), rooted in undefined surplus-collateral settlement rules when a stale close order triggers full-position liquidation.

## Key takeaway

No unconditional drain primitive against pool core reserves was found. The high-severity issue is a genuine **loss-of-maker-funds** path with a bounded, well-defined trigger, plus a cluster of medium/low accounting and settlement bugs in the new periphery.

---

*Full report file: [`AladdinDAO-fx-protocol-v2-audit-2026-04.md`](../AladdinDAO-fx-protocol-v2-audit-2026-04.md) — migrated from the original findings repo.*
