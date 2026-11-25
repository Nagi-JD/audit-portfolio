# Tower Exchange — Black-Box Security Audit

**Severity:** 🔴 4 Critical · 🟠 10 High · 18 Medium · 12 Low
**Type:** Web application, API, RPC infrastructure, AI transaction services and smart-contract integration
**Status:** Remediation reported by the Tower Exchange team for all 44 findings · independent retest pending

---

## Summary

Audit by SaturnBash, Kyrixa and Teres.

Black-box security assessment of the Tower Exchange platform: `tower.exchange`, the developer console, the analytics endpoints, the AI transaction services, the RPC proxies and the Arc testnet contracts. The first pass ran on 28–30 August 2026, with a verification pass on 11 September 2026.

## Findings by area

- **RPC infrastructure** — unauthenticated mempool exposure, open raw-transaction relay on mainnets, pending-transaction filter feed, open Solana RPC proxy, no rate limiting or batch caps.
- **AI transaction integrity** — prompt injection into transaction preparation, client-controlled transaction addresses, process-global execution context, unverified transaction confirmations.
- **API and analytics** — authentication bypass on undocumented routes, public wallet-level trade history, conversation and portfolio IDOR, developer key rotation weakness.
- **Swap and bridge safety** — ignored slippage, missing deadlines, client-supplied quotes trusted by the transaction builder, zero-address bridge recipient, unlimited approvals by default.
- **Application hardening** — clickjacking, disabled TLS verification in a service, hardcoded fallback key, missing security headers, session keys in browser storage.

## Outcome

Tower Exchange issued a remediation and closure report on 23 November 2026 stating that all 44 tracked findings have been fixed. The fixes are reported by the team; an independent retest has not been performed yet.

- [Full audit report](./TowerExchange_AUDIT.md)
- [Security Remediation & Fix Report (PDF)](./Tower_Exchange_Security_Remediation_Fix_Report.pdf)

