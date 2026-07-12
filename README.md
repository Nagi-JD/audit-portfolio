# Audit Portfolio — Saturn

Smart contract security research by **Saturn** (`Nagi-JD` on GitHub · `@Nagi97K` on [Cantina](https://cantina.xyz/u/Nagi97K)).
EVM (Foundry) & Solana (Anchor / Rust). Every finding here is backed by a write-up and, where the program allows, a passing proof-of-concept.

> Private, NDA and confidential engagements are not published here — available on request.

---

## Findings

| # | Protocol | Severity | Class | Status | Write-up |
|---|----------|----------|-------|--------|----------|
| 1 | [Suzaku](./suzaku) | 🔴 Critical | Intra-epoch validator stake inflation | ✅ Confirmed & fixed (PR #251) | [read](./suzaku) |
| 2 | [Hyperbridge](./hyperbridge) | 🟠 High | Handler storage poisoning by unprivileged EOA | Reported · PoC ✓ | [read](./hyperbridge) |
| 3 | [ThunderPick](./thunderpick) | 🟠 High | Application-layer security flaw | ✅ Confirmed · $1,500 awarded | [read](./thunderpick) |
| 4 | [AladdinDAO — f(x) v2](./aladdindao-fx-v2) | 🟠 High (+ 2 M, 4 L) | Maker surplus-collateral capture | Reported | [read](./aladdindao-fx-v2) |
| 5 | OnRe *(Solana)* | — | Program owner-check weakness | 🔒 Private | details on request |

---

## Approach

1. **Model the intended invariants** — what must always hold about value, ownership and accounting.
2. **Attack the assumptions** — cross-epoch state, stale orders, owner/authority checks, cross-VM encoding, rounding.
3. **Prove it** — a failing test that a fix must turn green. No proof, no claim.

## Stack

`Foundry` · `Solidity` / `Yul` · `Rust` · `Anchor` · `SPL` / `Token-2022` · fork testing · invariant / property tests

## Contact

- Cantina: **[Saturn (@Nagi97K)](https://cantina.xyz/u/Nagi97K)**
- HackenProof: **[saturndotbash](https://hackenproof.com/hackers/saturndotbash)**
- Discord: `saturncitizen`
- Email: `saturnbashct@proton.me`
