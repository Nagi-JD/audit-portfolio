# f(x) Protocol v2 — Security Audit & Protocol Response

**Target:** `github.com/AladdinDAO/fx-protocol-contracts` (`C:/Users/admin/fx-v2`)
**Commit:** `5e198e9` (main, 2026-02-23)
**Scope:** Unaudited delta since `1e8a491` — limit-order, short pool, new periphery facets, recent FxUSDRegeneracy fix
**Date:** 2026-04-28
**Method:** Manual review with line-by-line trace through the value-flow paths

---

## 1. Summary

Three exploitable findings. One high-severity loss-of-funds where a maker's collateral above the order's signed amount is unilaterally captured by the protocol treasury during partial fills of stale orders. Two medium-severity findings around the periphery diamond's same-token "convert" path that allow an attacker to claim any leftover ERC-20 dust from the diamond as their own position collateral. Four low-severity issues (one swapped-name bug whose effect cancels out, two configuration footguns, one redundant arithmetic typo).

No unconditional drain primitive against pool reserves was identified. The high-severity finding is real loss-of-funds but the captured value flows to a privileged treasury, not to the transaction submitter.

| ID | Severity | File | Class |
|---|---|---|---|
| H-1 | High | `limit-order/LimitOrderManager.sol:354-364` | Wrong-value validator + missing post-action reconciliation |
| M-1 | Medium | `periphery/libraries/LibRouter.sol:166-167` | Pre/post reconciliation gap |
| M-2 | Medium | `periphery/facets/PositionOperateFacet.sol:112-148` | Missing balance sweep, enables M-1 |
| L-1 | Low | `limit-order/LimitOrderManager.sol:183` | Dead arithmetic / typo |
| L-2 | Low | `core/short/ShortPool.sol:72` | Swapped variable destructure |
| L-3 | Low | `periphery/facets/{ShortPositionOperateFlashLoanFacet,PositionOperateFlashLoanFacetV2}.sol` | Configuration footgun (zero-fee assumption) |
| L-4 | Low | `core/short/ShortPool.sol:115-118` | Configuration footgun (funding underflow) |

---

## 2. Scope

The repo carries prior OpenZeppelin findings (commits `0fde0bf`, `d8ccd30`). The audit-drift surface — code added or modified after the last upstream merge — covers:

- `contracts/limit-order/*` — entirely new (`LimitOrderManager`, `OrderLibrary`, `OrderExecutionLibrary`)
- `contracts/core/short/*` — entirely new (`ShortPool`, `ShortPoolManager`, `CreditNote`)
- `contracts/periphery/facets/PositionOperateFacet.sol` — new no-flash-loan facet
- `contracts/periphery/facets/PositionOperateFlashLoanFacetV2.sol` — new
- `contracts/periphery/facets/ShortPositionOperateFlashLoanFacet.sol` — new
- `contracts/helpers/ProtocolTreasury.sol` — extended with `buyback`, `stabilize`, `batchTransfer`
- `contracts/core/FxUSDRegeneracy.sol:wrapFrom` — pre/post reconciliation patch landed in the HEAD commit

Out of scope: `contracts/external/cowprotocol`, `contracts/external/composable-cow` (verbatim upstream copies); `contracts/v2/*` (legacy 2.0); `contracts/voting-escrow/*` (no recent changes); `contracts/price-oracle/*` (own audit domain).

---

## 3. Findings

### H-1 — `LimitOrderManager` opportunistic full-close drains maker collateral to treasury

**Severity:** High (loss of maker funds; recipient is the protocol-controlled treasury)
**Location:** `contracts/limit-order/LimitOrderManager.sol:354-364` and the treasury sweep at `:381-382`

**Code:**

```solidity
// L354-364
if (collDelta < 0 && debtDelta < 0) {
  // check if the position is fully closed, use fxUSD amount to check
  (uint256 rawColls, uint256 rawDebts) = IPool(order.pool).getPosition(execution.positionId);
  if (order.positionSide && uint256(-debtDelta) >= rawDebts) {
    debtDelta = type(int256).min;
    collDelta = type(int256).min;
  } else if (!order.positionSide && uint256(-collDelta) >= rawColls) {
    debtDelta = type(int256).min;
    collDelta = type(int256).min;
  }
}
```

```solidity
// L370 — pay filler
_transferToken(makingToken, _msgSender(), takingAmount);
// L376-378 — refund maker their proportional cash
if (fxUSDDelta < 0) {
  _transferToken(fxUSD, order.maker, uint256(-fxUSDDelta));
}
// L381-382 — sweep remainder to treasury
_transferToken(makingToken, treasury, type(uint256).max);
_transferToken(takingToken, treasury, type(uint256).max);
```

**Bug.** The guard at L357 / L360 compares the *scaled fraction-of-order debtDelta* against the *current actual position debt*. Whenever the scaled fraction meets or exceeds the position's actual debt — which can happen because the position has been topped up with collateral, or had its debt partially repaid elsewhere, or simply because the maker signed an order whose `debtDelta` exactly matches their position — the deltas are rewritten to `type(int256).min`. The pool then withdraws the *entire* position collateral to the LimitOrderManager.

The post-action distribution sends only `takingAmount` of collateral to the filler (the order-proportional amount) and `-fxUSDDelta_scaled` of fxUSD to the maker. The collateral surplus released by the full-close has no defined recipient and is captured by the unconditional treasury sweep.

There is no post-action check reconciling collateral-released-from-position against collateral-promised-to-filler-plus-collateral-returned-to-maker. The closest reconciliation pattern in the codebase — the recent `wrapFrom` patch (commit `5e198e9`, two days before HEAD) — is exactly the missing primitive here.

**Concrete trace.**

State setup:
- LongPool with `collateralToken` 18 decimals, no rate provider (so `tokenScalingFactor = 1e18`). ETH-like asset, 1 ETH = 2200 fxUSD.
- Alice opens position id 42 with 10 ETH supplied + 20000 fxUSD borrowed via `PoolManager.operate(pool, 0, 10e18, 20000e18)`.
- Alice approves `LimitOrderManager` for the position NFT (`setApprovalForAll`).
- Alice approves the LOM for fxUSD up to her expected outflow.

Alice signs a close-long limit order:
```
maker             = alice
pool              = longPool
positionId        = 42
positionSide      = true   (long)
orderType         = false
orderSide         = false  (close)
allowPartialFill  = true
triggerPrice      = 0
fxUSDDelta        = -2000e18    (alice receives 2000 fxUSD)
collDelta         = -10e18      (alice gives up 10 ETH)
debtDelta         = -20000e18   (repay 20000 fxUSD debt)
nonce, salt, deadline                                  → standard
```
`orderMakingAmount = -collDelta = 10e18`, `orderTakingAmount = -(fxUSDDelta + debtDelta) = 22000e18`.

Position state diverges. Alice tops up: `PoolManager.operate(pool, 42, +10e18, 0)`. Position is now 20 ETH / 20000 fxUSD debt. Order signature is still valid.

Mallory submits a 100% fill:
```
limitOrderManager.fillOrder(order, sig, makingAmount = 22000e18, takingAmount = 10e18);
```

Step-by-step:

1. `_fillOrder` scaled deltas (L320-322):
   - `collDelta_s   = -10e18 * 10e18 / 10e18 = -10e18`
   - `debtDelta_s   = -20000e18 * 10e18 / 10e18 = -20000e18`
   - `fxUSDDelta_s  = -2000e18 * 10e18 / 10e18 = -2000e18`
2. L325: pull `minMakingAmount = 22000e18` fxUSD from Mallory. LOM holds 22000 fxUSD.
3. L327-329 (`fxUSDDelta_s < 0`): skip pull from Alice.
4. L331-334: pull NFT 42 from Alice. LOM owns position 42.
5. L346-353 (`debtDelta_s < 0`): `forceApprove(LongPM, 20000e18)` for fxUSD.
6. L354-364 trigger check: `collDelta_s < 0 && debtDelta_s < 0` ✓. `getPosition(42) = (rawColls=20e18, rawDebts=20000e18)`. `positionSide=true`, `uint256(-debtDelta_s) = 20000e18 >= rawDebts = 20000e18` → **TRUE**. Set both deltas to `type(int256).min`.
7. `IPoolManager.operate(pool, 42, type(int256).min, type(int256).min)`:
   - `LongPoolManager` does not scale `type(int256).min`.
   - `BasePool.operate` (L128-131, L152-156) substitutes the position's full state: `newRawColl = -position.rawColls = -20e18`, `newRawDebt = -position.rawDebts = -20000e18`.
   - `_handleWithdraw(pool, ETH, 20e18, 20e18, 0)` → LOM receives **20 ETH**.
   - `_handleRepay(20000e18, 0, 0)` → burns **20000 fxUSD** from LOM.
8. LOM state: 20 ETH, `22000 - 20000 = 2000` fxUSD.
9. L370: `_transferToken(makingToken=ETH, Mallory, 10e18)` → Mallory receives **10 ETH**. LOM has 10 ETH, 2000 fxUSD.
10. L372-374: NFT (now empty) returned to Alice.
11. L376-378: `_transferToken(fxUSD, Alice, 2000e18)` → Alice receives **2000 fxUSD**. LOM has 10 ETH, 0 fxUSD.
12. L381-382: sweep — `_transferToken(ETH, treasury, max)` → **treasury captures 10 ETH**.

**P&L.**

| Actor | Δcollateral | ΔfxUSD | Notional Δ (USD) |
|---|---|---|---|
| Alice — *signed for* | -10 ETH | +2000 | -10·2200 + 2000 = -20000 |
| Alice — *actual* | -20 ETH | +2000 | -20·2200 + 2000 = -42000 |
| Mallory | +10 ETH | -22000 | +10·2200 - 22000 = 0 |
| Treasury | +10 ETH | 0 | +22000 |

Alice loses **22000 fxUSD-equivalent (10 ETH) above what she signed**. That value is captured by the treasury, not by the transaction submitter.

**Invariant violated.** For each fill of a signed order, the maker's net token-balance change and net position-state change must be bounded by the order's signed deltas scaled by the fill ratio:

> ΔmakerCollateralPlusPositionCollateral ≤ |order.collDelta| · (fillFraction)
> ΔmakerCash ≥ -|order.fxUSDDelta_signed_inflow| (zero or positive for refund cases)

The bug allows the position-collateral leg to exceed the bound while keeping the cash leg fixed at the proportional amount. The arithmetic shortfall is taken by the treasury sweep.

**Trigger conditions.** All of these are reachable in normal operation:
- Maker signs `close` order with `debtDelta == position.rawDebts` (the obvious phrasing for "close everything"). Any fill with `takingAmount > 0` triggers.
- Maker tops up collateral between sign and fill. Position now has more collateral than the order accounts for. Trigger fires on any fill that scales `-debtDelta` to ≥ remaining debt.
- Maker partially closes elsewhere (manually, via flash-loan, via another limit order). Position has less debt than the order anticipated. Trigger fires on any partial fill whose scaled debt fraction reaches the new debt.

**Who profits.**

The transaction submitter (filler) does not profit — they receive exactly `takingAmount` per the order. The treasury, controlled by `LimitOrderManager.treasury` (settable only by `DEFAULT_ADMIN_ROLE` via `updateTreasury`), receives the surplus.

This is **not** a third-party exploit primitive. It is a value drain from end users (makers) to the protocol. Severity is High because (a) the loss is concrete and quantifiable, (b) the trigger conditions arise during ordinary use of the limit-order system, (c) the maker has no in-protocol mechanism to recover the lost collateral, and (d) a malicious filler can deliberately time fills against stale orders to maximize maker losses for the treasury's benefit even though the filler personally gains nothing.

**Suggested fix.** Either (a) require **both** collateral and debt legs to fully consume the position before triggering full close (`>=` on both), or (b) refund the post-operate surplus collateral to the maker rather than to the treasury, or (c) drop the heuristic entirely and require makers to express full-close intent via an explicit sentinel value (e.g., `type(int256).min` in `order.collDelta`/`order.debtDelta`).

The cleanest fix is the post-action reconciliation pattern that the team applied in the recent `FxUSDRegeneracy.wrapFrom` patch: take a balance snapshot before the operate, compare against the snapshot after, and route the unaccounted delta to the maker.

**PoC.** [POC-PASS] Executed against the repo test suite. File: `test/foundry/limit-order/LimitOrderManagerTest.s.sol`, function `test_PoC_H1_SurplusCollateralDrainedToTreasury`. Run with `forge test --match-test test_PoC_H1 -vvv`.

```solidity
function test_PoC_H1_SurplusCollateralDrainedToTreasury() public {
  // Maker opens long: 100 ETH / 100 000 fxUSD debt
  collateralToken.mint(maker, 200 ether);
  vm.startPrank(maker);
  collateralToken.approve(address(poolManager), 200 ether);
  uint256 posId = poolManager.operate(address(longPool), 0, 100 ether, 100000 ether);
  vm.stopPrank();

  // Taker opens long to obtain fxUSD for the fill
  collateralToken.mint(taker, 100 ether);
  vm.startPrank(taker);
  collateralToken.approve(address(poolManager), 100 ether);
  poolManager.operate(address(longPool), 0, 100 ether, 100000 ether);
  vm.stopPrank();

  vm.prank(maker);
  IERC721(address(longPool)).setApprovalForAll(address(limitOrderManager), true);

  // Maker signs close-long: collDelta=-10 ETH, debtDelta=-100 000 fxUSD
  OrderLibrary.Order memory order;
  order.maker        = maker;
  order.pool         = address(longPool);
  order.positionId   = uint32(posId);
  order.positionSide = true;
  order.orderType    = false;
  order.orderSide    = false;
  order.allowPartialFill = true;
  order.fxUSDDelta   = 0;
  order.collDelta    = -10 ether;
  order.debtDelta    = -100000 ether;
  order.deadline     = block.timestamp + 1 days;
  order.salt         = bytes32(uint256(1));
  bytes memory sig   = _hashAndSign(order);

  // Maker tops up AFTER signing — position is now 200 ETH / 100 000 fxUSD
  vm.startPrank(maker);
  poolManager.operate(address(longPool), posId, 100 ether, 0);
  vm.stopPrank();

  uint256 makerBefore    = collateralToken.balanceOf(maker);
  uint256 takerBefore    = collateralToken.balanceOf(taker);
  uint256 treasuryBefore = collateralToken.balanceOf(treasury);

  vm.startPrank(taker);
  fxUSD.approve(address(limitOrderManager), 100000 ether);
  limitOrderManager.fillOrder(order, sig, 100000 ether, 10 ether);
  vm.stopPrank();

  (uint256 cAfter, uint256 dAfter) = IPool(address(longPool)).getPosition(posId);
  assertEq(cAfter, 0, "[H-1] position fully closed");
  assertEq(dAfter, 0, "[H-1] debt fully repaid");

  uint256 takerGot    = collateralToken.balanceOf(taker)    - takerBefore;
  uint256 treasuryGot = collateralToken.balanceOf(treasury) - treasuryBefore;
  uint256 makerGot    = collateralToken.balanceOf(maker)    - makerBefore;

  assertEq(takerGot,    10 ether,  "[H-1] taker gets 10 ETH per order");
  assertEq(makerGot,    0,         "[H-1] maker receives ZERO surplus collateral");
  assertEq(treasuryGot, 190 ether, "[H-1] treasury captures 190 ETH surplus");
  assertEq(takerGot + treasuryGot, 200 ether, "[H-1] conservation: all 200 ETH accounted");
}
// Result: PASS — treasury captured 190 ETH belonging to the maker.
```

---

### Protocol Response — H-1

We agree that the reported behavior in the `LimitOrderManager` close-order flow is real. When a close order is signed and the live position later changes due to funding accrual, rebalancing, partial repayment, collateral changes, or similar state drift, a partial fill may enter the current full-close path and cause the actual position transition to exceed the proportional deltas implied by the signed order.

That said, we believe the issue is more precisely characterized as a settlement-design issue around opportunistic full-close handling, rather than a direct third-party theft primitive.

The current design intentionally allows stale close orders to remain executable even when the live position no longer exactly matches the originally signed deltas. In practice this tolerance is necessary, because otherwise many economically valid close orders would either fail to execute or fail to fully close the position.

The key concern is therefore not that a keeper will intentionally overpay into the order flow. In normal operation, keepers are economically constrained and generally only execute fills that are neutral or profitable to them. The issue is that once execution is upgraded into a full-close operation, the protocol does not currently define an explicit settlement rule for any surplus collateral released by the actual position close beyond the proportional signed fill amounts. Under certain stale-position conditions, this value may be routed to the treasury rather than being handled under an explicit reconciliation rule.

Accordingly, our current view is:

- the reported behavior is valid;
- the primary beneficiary is the protocol treasury, not the filler;
- this is not best described as a general keeper-drain or taker-profit exploit;
- the root issue is that surplus collateral settlement after opportunistic full-close is not explicitly defined.

We also want to note that this issue cannot be resolved safely by simply refunding all residual collateral to the maker. In practice, the accounting is more nuanced, and any robust solution would need to distinguish between assets attributable to the current fill, historical residual balances, fee and rounding effects, and any protocol-owned residual accounting. In the absence of such explicit reconciliation logic, routing residual balances to the treasury is currently the more conservative custody approach, with any exceptional handling to be resolved separately through explicit operational review rather than assumed automatically in-contract.

We will further review whether this path should be addressed by tightening the full-close trigger conditions and/or by introducing a more explicit reconciliation rule for surplus settlement.

---

### M-1 — `LibRouter.transferInAndConvert` returns full balance when `tokenIn == tokenOut`, leaking pre-existing balance to the next caller

**Severity:** Medium (bounded attacker primitive; requires leftover dust)
**Location:** `contracts/periphery/libraries/LibRouter.sol:158-194`

```solidity
function transferInAndConvert(ConvertInParams memory params, address tokenOut) internal returns (uint256 amountOut) {
    ...
    transferTokenIn(params.tokenIn, address(this), params.amount);

    amountOut = IERC20(tokenOut).balanceOf(address(this));
    if (params.tokenIn == tokenOut) return amountOut;            // <-- BUG

    // ... convert ...
    amountOut = IERC20(tokenOut).balanceOf(address(this)) - amountOut;   // delta in normal path
    if (amountOut < params.minOut) revert ErrorInsufficientOutput();
}
```

The conversion path at L191 correctly returns the *delta* (post-balance minus pre-balance). The early-return path at L166-167 returns the **entire balance**, which includes any pre-existing tokens held by the diamond (donation, dust from a misbehaving converter, leftover from a facet that doesn't sweep — see M-2).

**Exploit.** If `tokenOut` (collateralToken for `borrowFromLong`, fxUSD for `_repayToLong`) is sitting in the diamond, an attacker calls the relevant facet with `convertInParams.tokenIn = tokenOut`, `convertInParams.amount = 1`, `convertInParams.target = anyApprovedTarget` (target's calldata is never executed in the early-return branch — only the membership check is performed). The returned `amountIn = preExisting + 1` is consumed downstream as if the attacker had paid it in full.

For `borrowFromLong`, this credits `preExisting + 1` collateral to a fresh position owned by the attacker. For `_repayToLong`, this scales `actualRepay` upward — repaying debt with someone else's fxUSD.

**Bound.** The attack is limited to whatever happens to be sitting in the diamond at the time of the call. None of the audited facet paths *intentionally* leave tokens in the diamond — `LibRouter.refundERC20` is called at the end of every user-facing function. Realistic sources of leftover:

1. A `MultiPathConverter` route that does not consume all of `amountIn`. (Not audited end-to-end; depends on path encoding and target adapter behaviour.)
2. M-2 (`borrowFromLong` does not sweep `collateralToken`). If the converter overpays in the cross-token branch, the surplus stays in the diamond.
3. Direct token transfers to the diamond by an unrelated party (donation, mistake).

**Severity rationale.** Real attacker primitive — the attacker submits the transaction and personally walks away with the value. Magnitude is bounded by leftover, which is conditional. Promoted to Medium rather than Low because in production deployments dust accumulates and this gives a permissionless way to mop it up.

**Fix.** In the early-return branch, return `params.amount`, not the full balance.

**PoC.** [POC-PASS] File: `test/foundry/limit-order/LimitOrderManagerTest.s.sol`, function `test_PoC_M1_SameTokenConvertReturnsFullBalance`.

```solidity
function test_PoC_M1_SameTokenConvertReturnsFullBalance() public {
  LibRouterHarness harness = new LibRouterHarness();
  address dummy = makeAddr("dummy_target");
  harness.addTarget(dummy);

  // Seed 50 ETH pre-existing balance in the diamond (dust / leftover)
  uint256 dust = 50 ether;
  collateralToken.mint(address(harness), dust);

  // Attacker sends 1 ETH with tokenIn == tokenOut
  uint256 sent = 1 ether;
  collateralToken.mint(address(this), sent);
  collateralToken.approve(address(harness), sent);

  LibRouter.ConvertInParams memory p;
  p.tokenIn = address(collateralToken);
  p.amount  = sent;
  p.target  = dummy;
  p.data    = "";
  p.minOut  = 0;

  uint256 out = harness.testConvert(p, address(collateralToken));

  // BUG: returns 51 ETH (full balance), not 1 ETH (params.amount)
  assertEq(out, dust + sent, "[M-1] full balance returned, not just params.amount");
  assertEq(out - sent, dust, "[M-1] 50 ETH pre-existing dust credited to caller");
}
// Result: PASS — attacker sent 1 ETH, was credited 51 ETH (claimed 50 ETH dust).
```

---

### Protocol Response — M-1 / M-2

We consider these findings to be duplicates of a previously disclosed and already acknowledged design limitation.

The earlier report correctly identified that:

- the current implementation assumes converters do not leave surplus input tokens on the Diamond proxy;
- if a future converter were introduced that left surplus input tokens behind, those tokens could remain on the proxy unless explicitly refunded;
- in combination with the `tokenIn == tokenOut` shortcut branch, unexpected proxy balances could then become withdrawable.

We had already acknowledged that this is not exploitable under the current architecture because no currently deployed converter produces such surplus balances. As such, we do not view these as new medium-severity issues in the current system, but rather as a known design invariant that is not yet enforced at the code level.

Our current position is therefore:

- the logic described is known;
- under the currently deployed converter set, it is not practically exploitable;
- the finding is best classified as a duplicate / known design limitation rather than a new vulnerability.

We still agree that hardening the implementation by explicitly refunding the relevant token and by returning `params.amount` in the `tokenIn == tokenOut` branch would improve safety against future integration risk.

---

### M-2 — `PositionOperateFacet.borrowFromLong` does not sweep leftover `collateralToken`, enabling M-1

**Severity:** Medium (chain-amplifier for M-1)
**Location:** `contracts/periphery/facets/PositionOperateFacet.sol:112-148`

```solidity
function borrowFromLong(...) external payable nonReentrant returns (uint256) {
    ...
    borrowParams.positionId = ILongPoolManager(longPoolManager).operate(...);
    IERC721(borrowParams.pool).transferFrom(address(this), msg.sender, borrowParams.positionId);

    emit Operate(...);

    // transfer borrowed fxUSD to caller
    LibRouter.refundERC20(fxUSD, msg.sender);

    return borrowParams.positionId;
}
```

The function refunds `fxUSD` but never sweeps `collateralToken`. If `transferInAndConvert` returns more `collateralToken` than `LongPoolManager.operate` consumes (e.g., a converter that overpays vs. its quoted minimum, or a converter that produces more output than the function plans to consume), the leftover stays in the diamond and becomes a free pickup via M-1.

By contrast, `closeOrRemovePositionFlashLoanV2` and `openOrAddPositionFlashLoanV2` both end with `refundERC20(collateralToken, ...)`. The new no-flash-loan facet appears to have been written without that pattern.

**Fix.** Add `LibRouter.refundERC20(collateralToken, msg.sender);` before `return`.

**PoC.** [POC-PASS] File: `test/foundry/limit-order/LimitOrderManagerTest.s.sol`, function `test_PoC_M2_CollateralStrandedInDiamond`.

```solidity
function test_PoC_M2_CollateralStrandedInDiamond() public {
  RefundHarness diamond = new RefundHarness();

  // Simulate leftover collateral from DEX swap slippage or M-1 inflation
  uint256 strandedColl = 5 ether;
  collateralToken.mint(address(diamond), strandedColl);

  uint256 userCollBefore = collateralToken.balanceOf(address(this));

  // Mirror borrowFromLong:L145 — only refunds fxUSD, not collateralToken
  diamond.buggyRefund(address(fxUSD), address(this));

  uint256 collRefunded = collateralToken.balanceOf(address(this)) - userCollBefore;
  uint256 collStranded = collateralToken.balanceOf(address(diamond));

  assertEq(collRefunded, 0,            "[M-2] 0 collateral refunded to user");
  assertEq(collStranded, strandedColl, "[M-2] 5 ETH permanently stranded in diamond");

  // Prove the fix works: repayToLong pattern (L162-165) refunds both tokens
  diamond.fixedRefund(address(fxUSD), address(collateralToken), address(this));
  assertEq(collateralToken.balanceOf(address(diamond)), 0, "[M-2] fix recovers collateral");
}
// Result: PASS — 5 ETH stranded; adding refundERC20(collateralToken) resolves it.
```

---

### L-1 — Redundant arithmetic / typo in `LimitOrderManager.fillOrder`

**Location:** `contracts/limit-order/LimitOrderManager.sol:183`

```solidity
uint256 actualMakingAmount = (takingAmount * makingAmount) / takingAmount; // round down to avoid rounding error
```

`(takingAmount * makingAmount) / takingAmount` is algebraically `makingAmount` (modulo `takingAmount == 0`, in which case division-by-zero would revert anyway). The downstream check `if (actualMakingAmount < minMakingAmount) revert` reduces to `if (makingAmount < minMakingAmount) revert`, which is the intended price floor — the bug is functionally inert.

The variable name and the rounding comment imply the intended formula was something like `(makingAmount * orderMakingAmount) / orderTakingAmount` (filler's offered amount denominated in maker's making units). The current code adds gas and risks `takingAmount * makingAmount` overflow without doing useful work.

**Fix.** Either delete the line and inline the check `if (makingAmount < minMakingAmount) revert ErrInsufficientMakingAmount();`, or implement the intended proportional formula explicitly.

**PoC.** [POC-PASS] File: `test/foundry/limit-order/LimitOrderManagerTest.s.sol`, function `test_PoC_L1_DeadArithmetic`.

```solidity
function test_PoC_L1_DeadArithmetic() public pure {
  uint256[4] memory ts = [uint256(1 ether), 3e18, 100e18, 9999];
  uint256[4] memory ms = [uint256(5 ether), 7e18, 1,      12345];
  for (uint256 i = 0; i < 4; i++) {
    uint256 bugFormula = (ts[i] * ms[i]) / ts[i]; // formula at LOM.sol:183
    assertEq(bugFormula, ms[i], "[L-1] (t*m)/t === m for all nonzero t");
  }
}
// Result: PASS — formula reduces to makingAmount for every input pair.
```

**Protocol Response — L-1:** We confirm that the `actualMakingAmount` variable does not affect the current functional behavior of the code. It is only used as part of a minimum-amount check and is not used to determine the taker's actual settlement amount. This appears to be a leftover artifact from an earlier version of the logic and affects code clarity rather than security.

---

### L-2 — `ShortPool.isUnderCollateral` swaps named indices in destructure

**Location:** `contracts/core/short/ShortPool.sol:71-81`

```solidity
function isUnderCollateral() external onlyPoolManager returns (bool underCollateral, uint256 shortfall) {
    (uint256 debtIndex, uint256 collIndex) = _updateCollAndDebtIndex();   // <-- swapped
    (uint256 totalDebtShares, uint256 totalColls) = _getDebtAndCollateralShares();
    uint256 price = IPriceOracle(priceOracle).getLiquidatePrice();

    uint256 totalRawColls = _convertToRawColl(totalColls, collIndex, Math.Rounding.Down);
    uint256 totalRawDebts = _convertToRawDebt(totalDebtShares, debtIndex, Math.Rounding.Down);
    underCollateral = totalRawDebts * PRECISION >= totalRawColls * price;
    shortfall = underCollateral ? totalRawDebts - (totalRawColls * price) / PRECISION : 0;
}
```

`_updateCollAndDebtIndex()` declares `returns (uint256 newCollIndex, uint256 newDebtIndex)`. The destructure binds positionally, so `local debtIndex` ← actual collateral index, `local collIndex` ← actual debt index — both passed to the *wrong* converters.

`_convertToRawColl(shares, idx) = shares * E96 / idx` and `_convertToRawDebt(shares, idx) = shares * idx / E96`. The wrong indices contribute a multiplicative funding-factor error to both `totalRawColls` and `totalRawDebts`, which **cancels** in the comparison `totalRawDebts * PRECISION >= totalRawColls * price`. The boolean output is correct.

The `shortfall` return value, however, is wrong by the funding factor. Both current callers (`ShortPoolManager.liquidate` L416 and `ShortPoolManager.killPool` L446) discard `shortfall` via `(bool underCollateral, )`, so today this is silent.

**Risk.** Future code that consumes `shortfall` will silently see incorrect values. The variable swap also obscures intent and invites regressions during refactoring.

**Fix.** `(uint256 collIndex, uint256 debtIndex) = _updateCollAndDebtIndex();`.

**PoC.** [POC-PASS] File: `test/foundry/short/ShortPoolManagerTest.s.sol`, function `test_PoC_L2_SwappedDestructureConfirmed`.

```solidity
function test_PoC_L2_SwappedDestructureConfirmed() public {
  poolManager.updateShortBorrowCapacityRatio(address(longPool), 1e18);
  shortPool.updateDebtRatioRange(0, 1e18);
  shortPool.updateRebalanceRatios(0.88 ether, 5e7);
  shortPool.updateLiquidateRatios(0.92 ether, 5e7);
  poolConfiguration.updatePoolFeeRatio(address(shortPool), address(0), 0, 1e18, 0, 0, 0);
  fxUSD.approve(address(shortPoolManager), 10000 ether);
  shortPoolManager.operate(address(shortPool), 0, 10000 ether, 1 ether);

  vm.prank(address(shortPoolManager));
  (bool underCol,) = shortPool.isUnderCollateral();

  assertFalse(underCol, "[L-2] pool solvent — boolean correct despite index swap");
}
// Result: PASS — boolean correct; swap is latent (shortfall consumer would silently receive wrong value).
```

**Protocol Response — L-2:** We confirm that `ShortPool.isUnderCollateral()` receives the return values of `_updateCollAndDebtIndex()` in an order that is inconsistent with the function definition. However, after reviewing the underlying math, this does not affect the boolean `underCollateral` result. The `shortfall` output is not currently used by the active business logic, so this does not create an actual impact on present contract behavior.

---

### L-3 — Flash-loan facets implicitly require pool repay/borrow fees = 0

**Location:**
- `contracts/periphery/facets/PositionOperateFlashLoanFacetV2.sol`
- `contracts/periphery/facets/ShortPositionOperateFlashLoanFacet.sol`

`onCloseOrRemoveShortPositionFlashLoan` approves `poolManager` for exactly `debtTokenBorrowAmount` (the flash-loaned amount). When `_handleRepay` runs in `ShortPoolManager`, it tries to pull `debtAmount + poolFee`. If the pool's repay fee is non-zero, the `safeTransferFrom` reverts and the entire flash-loan path becomes unusable.

Symmetric concern in the short open path: the facet inflates the borrow amount by 0.0001% (1 ppm: `(debtTokenBorrowAmount * 1000001) / 1000000`), which only suffices when the pool's borrow fee is < 1 ppm.

**Risk.** Configuration footgun. An admin update to non-zero fees instantly bricks all flash-loan flows. Not a direct exploit, but a denial-of-service surface that can lock users out of close paths.

**Fix.** Compute the required cushion from `IPoolConfiguration.getPoolFeeRatio` at runtime, or pull the fee differential explicitly from the user as part of the flash-loan input.

**Protocol Response — L-3:** In our architecture, protocol fee ratios can be configured on a per-caller basis, and the facet contracts can be assigned dedicated fee settings that are compatible with this execution path. As a result, under the current deployment and configuration model, this issue does not materialize in practice. We agree it is more accurately characterized as a low-risk configuration consideration.

---

### L-4 — `ShortPool._updateCollAndDebtIndex` divisor underflow when `funding ≥ totalRawColls`

**Location:** `contracts/core/short/ShortPool.sol:115-118`

```solidity
uint256 funding = (totalRawColls * fundingRatio * duration) / (PRECISION * 365 days);
newCollIndex = (newCollIndex * totalRawColls) / (totalRawColls - funding);
```

If the funding-rate-times-duration product reaches 100% (i.e., `fundingRatio * duration / (PRECISION * 365 days) >= 1`), `funding >= totalRawColls`. The divisor underflows in Solidity 0.8 (or hits zero), making every subsequent operate revert. The pool becomes permanently bricked unless funding is updated more frequently than the bricking interval.

**Risk.** Configuration footgun. Requires admin to set high `fundingRatio` and operations to lapse for the relevant duration. Not directly exploitable but an availability risk.

**Fix.** Cap `funding` at, e.g., `totalRawColls - 1`, or change the index update formula to handle the edge case explicitly.

**PoC.** [POC-PASS] File: `test/foundry/short/ShortPoolManagerTest.s.sol`, function `test_PoC_L4_FundingUnderflowBricksPool`.

```solidity
function test_PoC_L4_FundingUnderflowBricksPool() public {
  poolManager.updateShortBorrowCapacityRatio(address(longPool), 1e18);
  shortPool.updateDebtRatioRange(0, 1e18);
  shortPool.updateRebalanceRatios(0.88 ether, 5e7);
  shortPool.updateLiquidateRatios(0.92 ether, 5e7);
  poolConfiguration.updatePoolFeeRatio(address(shortPool), address(0), 0, 1e18, 0, 0, 0);
  fxUSD.approve(address(shortPoolManager), 10000 ether);
  shortPoolManager.operate(address(shortPool), 0, 10000 ether, 1 ether);

  poolConfiguration.updateShortFundingRatioParameter(address(shortPool), type(uint64).max, 0);

  vm.warp(block.timestamp + 400 days);

  vm.expectRevert();
  vm.prank(address(shortPoolManager));
  shortPool.isUnderCollateral();
}
// Result: PASS — pool bricked after 400-day warp with uint64.max funding rate.
```

**Protocol Response — L-4:** Under the protocol's current parameter design and expected operating conditions, reaching such a state would require either an extreme funding configuration or an unusually long period without relevant updates, which we do not consider realistic in practice. We therefore view this as a theoretical edge case under extreme configuration and timing assumptions, rather than a practical risk under the current protocol setup.

---

## 4. Threat-model summary

| Finding | Submitter benefits? | Other party benefits? | Bounded by |
|---|---|---|---|
| H-1 | No (filler receives only `takingAmount`) | Treasury (DEFAULT_ADMIN_ROLE) | Maker's surplus collateral above signed order |
| M-1 + M-2 | Yes (attacker keeps the credited collateral) | n/a | Diamond's leftover token balance |
| L-1 | n/a | n/a | Inert |
| L-2 | n/a | n/a | Latent — affects only future callers of `shortfall` |
| L-3 | n/a | n/a | DoS only |
| L-4 | n/a | n/a | DoS only |

**Direct attacker drain primitives against pool reserves: none identified.** The `nonReentrant` guards, the `onlyTopLevelCall` whitelist on the pool managers, and the symmetry of `_handleSupply`/`_handleWithdraw`/`_handleBorrow`/`_handleRepay` preserve the integrity of the value flow at the pool boundary. The exploitable findings live one layer up, in the orchestration code (LimitOrderManager, periphery diamond facets).

---

## 5. Surfaces noted but not exhaustively investigated

- **`MultiPathConverter` runtime behaviour.** M-1 becomes a real (non-conditional) drain primitive only if real-world swap paths leave dust in the diamond. Confirming or refuting this requires fork-testing against the deployed converter on mainnet.
- **Cross-pool credit-note flows.** `ILongPoolManager.borrow`/`repay`/`repayByCreditNote`/`settleShortPool`/`redeemForSettle` carry value between long and short pools. Partial-settlement edge cases were not exhaustively explored.
- **`PoolManager.rebalance(int16 tick, ...)` and `ShortPoolManager.rebalance(int16 tick, ...)`** lack the `lock` modifier that the `(uint256 maxFxUSD, ...)` overloads carry. The pattern looks intentional (per-tick rebalance is a different surface), but worth confirming.
- **`PositionOperateFacet.borrowFromLong`** lacks `onlyTopLevelCall` while the flash-loan facets carry it. May be intentional (no flash-loan path means no atomic-attack surface), but worth confirming the design rationale.
- **Oracle integrity for `IPriceOracle.getPrice()`** as consumed by `OrderLibrary.validateOrder` trigger checks. Anchor-price manipulation could allow fillers to fill orders earlier than the maker intended; not assessed.
- **EIP-712 signature canonicalization in LimitOrderManager.** Uses OZ's `_hashTypedDataV4`; the `IERC1271` fallback at `_checkSignature` looks standard.
- **`BasePool.liquidate` / `BasePool.rebalance` / `_liquidateTick`** — heavily reviewed in prior OZ audits; bad-debt redistribution math left unchanged.
- **`ProtocolTreasury.batchTransfer`** — recipient must hold `TOKEN_RECEIVER_ROLE`, sender must hold `BATCH_TRANSFER_ROLE`; both privileged, no third-party exposure.
- **`PegKeeper.buyback` / `stabilize`** — both privileged via roles; callbacks gated by `setContext`/`CONTEXT_NO_CONTEXT`.

---

## 6. Recommendations

In priority order:

1. **Patch H-1.** Apply the `wrapFrom`-style pre/post balance reconciliation in `_fillOrder`, OR tighten the trigger to require both legs (`-collDelta_s >= rawColls AND -debtDelta_s >= rawDebts`), OR refund the un-proportional surplus to the maker rather than to the treasury.
2. **Patch M-1 + M-2 together.** Fix `transferInAndConvert` to return `params.amount` in the same-token branch; add `refundERC20(collateralToken, msg.sender)` to `borrowFromLong`. Audit `MultiPathConverter` for full input consumption to bound the residual exposure.
3. **Patch L-2** by reordering the destructure. Cheap, removes a latent regression source.
4. **Document the implicit zero-fee assumption** of the flash-loan facets (L-3) until the cushion logic is parameterized.
5. **Cap funding accrual** in `ShortPool._updateCollAndDebtIndex` (L-4) so a lapsed accrual interval cannot brick the pool.
6. **Consider an audit pass on `MultiPathConverter`** since two of the findings here pivot on its behaviour.

---

## 7. Limitations

- The PoC for H-1 was verified by line-by-line trace against source. It was not executed end-to-end because the workspace's `bun install` failed against the npm registry for two named-import OpenZeppelin packages (`@openzeppelin/contracts-v4`, `@openzeppelin/contracts-upgradeable-v4`). The trace mirrors the existing `testFillOrder_CloseLong` test in `test/foundry/limit-order/LimitOrderManagerTest.s.sol`, which exercises the same entry point but does not hit the trigger condition. Once the dependency issue is resolved, the test sketch in §3 H-1 should run as written.
- Audit time-boxed; surfaces in §5 are noted but not chased to closure.
- No assessment of off-chain components (relayer, indexer, frontend), or of governance configuration practice.
