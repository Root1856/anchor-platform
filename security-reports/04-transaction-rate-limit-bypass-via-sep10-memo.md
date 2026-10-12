# Proof of Concept

## Title
Per-identity transaction-creation rate limit (`rate_limit`) is bypassable: one keypair obtains unlimited independent buckets via the SEP-10 `memo` parameter (anchor-platform ≤ 4.9.0)

## Description

### Summary:
The Anchor Platform offers a rate limit on transaction creation (SEP-6/24/31) "per authenticated SEP-10 identity" (`rate_limit.enabled`, `max_transactions_per_window`, `window_seconds`). The limiter keys its buckets on the token's owner account **and memo**:

```java
// platform/src/main/java/org/stellar/anchor/platform/utils/TransactionCreationRateLimiter.java:37
String identity = token.getOwnerAccount() + ":" + token.getOwnerMemo();
```

But the SEP-10 challenge endpoint lets *any* (non-custodial) account request a challenge with an arbitrary `memo` – the only validation is that it parses as a uint64 (`core/src/main/java/org/stellar/anchor/sep10/Sep10Service.java:211-223`) – and the issued JWT then carries `sub = G...:<memo>` (`:564-574`). Nothing ties a memo to a custodial-wallet configuration: the attacker's own keypair signs the challenge, so `G:1`, `G:2`, …, `G:N` are all valid identities for one attacker. Muxed addresses (`M...`) of the same `G` give the same effect.

Consequently, with the limiter enabled, an attacker needs N cheap, unauthenticated-at-creation challenge round-trips to obtain N × `max_transactions_per_window` transaction creations per window, which defeats the control's purpose (protecting the database, the event stream and the business server's `/rate`, `/customer` callbacks from one abusive identity). The limiter is off by default, so this only affects anchors that enabled it as a mitigation.

### Steps To Reproduce:
Local instance with `rate_limit.enabled=true`, `rate_limit.max_transactions_per_window=2`, `rate_limit.window_seconds=60`, SEP-10 and SEP-24 enabled.

  1. Generate one keypair `G`. Obtain a SEP-10 JWT **without** memo (`GET /auth?account=G` → sign → `POST /auth`). Create 3 SEP-24 deposits:
     ```
     for i in 1 2 3; do curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/sep24/transactions/deposit/interactive \
       -H "Authorization: Bearer $JWT0" -H 'Content-Type: application/json' -d '{"asset_code":"USDC"}'; done
     # -> 200 200 429   (limit works for a single identity)
     ```
  2. With the **same keypair**, obtain additional JWTs using distinct memos: `GET /auth?account=G&memo=1`, `GET /auth?account=G&memo=2`, … and sign/submit each challenge. Each returns a token whose `sub` is `G:1`, `G:2`, …
  3. Repeat step 1 with each memo-token:
     ```
     for m in 1 2 3 4 5; do for i in 1 2; do curl -s -o /dev/null -w '%{http_code} ' -X POST http://localhost:8080/sep24/transactions/deposit/interactive \
       -H "Authorization: Bearer ${JWT[$m]}" -H 'Content-Type: application/json' -d '{"asset_code":"USDC"}'; done; done
     # -> 200 200 200 200 200 200 200 200 200 200  (10 more creations inside the same 60 s window)
     ```
  4. Observe in the database/Platform API that all 12 transactions were created within one window by the same Stellar account `G`, i.e. the configured limit of 2 was never enforced against the real principal.

### Supporting Material:
  * `platform/src/main/java/org/stellar/anchor/platform/utils/TransactionCreationRateLimiter.java:33-45`
  * `core/src/main/java/org/stellar/anchor/sep10/Sep10Service.java:211-223, 564-574`
  * `platform/src/main/resources/config/anchor-config-default-values.yaml` (`rate_limit` section: "per authenticated SEP-10 identity")
  * Suggested fix: key the limiter on the base account (`token.getAccount()`), treating memo / muxed sub-accounts of the same `G` as one principal (optionally keep a secondary per-sub-id bucket), and/or additionally rate-limit by source IP.

## Impact

### Summary:
Availability / abuse-control bypass. An attacker with a single keypair can create an unbounded number of SEP-6/24/31 transactions per window despite `rate_limit` being enabled, flooding the anchor's database, Kafka/event stream and business-server callbacks – exactly the abuse the control exists to prevent. Low severity because the limiter is opt-in and the attacker still needs a valid (self-signed) SEP-10 session per bucket. CVSS v3.1: 4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L).
