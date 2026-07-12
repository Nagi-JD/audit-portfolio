# Hyperbridge — HandlerV2 Storage Poisoning by an Unprivileged EOA

**Severity:** 🟠 High
**Type:** Access control / storage corruption
**Status:** Reported (Hackenproof) · PoC ✓
**Chain / stack:** EVM · Foundry fork test

---

## Summary

An unprivileged externally-owned account (EOA) can permanently corrupt `HandlerV2`'s storage. A fork proof-of-concept drives the contract from a clean state into a poisoned one that no privileged role authorized, permanently altering handler bookkeeping.

## Proof of concept

Fork test (`test_H02_fork`) run against Ethereum state:

```
[PASS] test_H02_fork_attacker_corrupts_HandlerV2_storage() (gas: 371151)
Logs:
  currentEpoch() before attack: 0
  currentEpoch() after attack:  18446744073709551615
  relayerOf(u64::MAX) after attack: 0xef8d813D387eA504ba11dDc2a3cA448125E86f56
  [POC-PASS] HandlerV2 storage permanently corrupted by unprivileged EOA
Suite result: ok. 1 passed; 0 failed; 0 skipped
```

The attacker, with no special role, moves `currentEpoch()` to `u64::MAX` and installs an attacker-controlled address as `relayerOf(u64::MAX)` — state that should only ever be reachable through privileged, validated transitions.

## Impact

- Core handler accounting (epoch, relayer mapping) is driven into an attacker-chosen, permanent state.
- Downstream logic that trusts `currentEpoch()` / `relayerOf(...)` operates on forged values, enabling further abuse of the cross-chain message path.

## Status & disclosure

Reported through Hackenproof. Full exploit contract and the corrupted-state assertions are available on request / within the program's disclosure rules.

*Full report: [`HYPERBR-44.pdf`](./HYPERBR-44.pdf).*
