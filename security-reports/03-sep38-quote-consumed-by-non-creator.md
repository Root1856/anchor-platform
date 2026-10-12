# Proof of Concept

## Title
Missing ownership check when a SEP-38 `quote_id` is consumed by SEP-6/SEP-24/SEP-31 – any authenticated user can bind and burn another customer's firm quote (anchor-platform ≤ 4.9.0)

## Description

### Summary:
SEP-38 firm quotes are created per customer: `POST /sep38/quote` stores `creatorAccountId`, `creatorMemo` and `creatorMemoType` from the SEP-10 token (`core/src/main/java/org/stellar/anchor/sep38/Sep38Service.java:283-286`), and the rate is requested from the business server with `client_id = <token account>` (`:353-357`, `:549-552`), so prices/fees can legitimately differ per customer. `GET /sep38/quote/{id}` enforces that only the creator can read the quote (`Sep38Service.java:439-446`).

Every code path that **consumes** a quote, however, never compares the quote's creator with the caller:

* `core/src/main/java/org/stellar/anchor/util/ExchangeAmountsCalculator.java:110-177` (`validateQuoteAgainstRequestInfo`) – checks existence, `transactionId == null`, expiry, asset/amount/delivery-method match. The method does not even receive the token. Used by SEP-6 deposit-exchange / withdraw-exchange (`Sep6Service.java:242-245`, `:440-443`) and SEP-24 deposit / withdraw (`Sep24Service.java:583-604`, called from `:218-237` and `:380-399`).
* `core/src/main/java/org/stellar/anchor/sep31/Sep31Service.java:702-766` (`preValidateQuote`) – same set of checks, no creator comparison.
* After validation the quote is permanently bound to the caller's transaction via `bindQuoteToTransaction` (`ExchangeAmountsCalculator.java:187-192` → `JdbcSep38QuoteRepo` `UPDATE … SET transaction_id=:txn WHERE transaction_id IS NULL`), after which the legitimate owner gets `quote(id=…) has already been used`.

Result: any wallet user B who learns the quote id Q of another customer A can (1) create a SEP-6/24/31 transaction priced with A's firm quote (including any client-specific rate/fee the business server granted to A), and (2) irrevocably consume Q so that A's own transaction creation fails. The platform already treats the quote as customer-private on the read path, so the write path is inconsistent with the implemented authorization model.

Exploitability note (stated for accuracy): quote ids are whatever the business server returns from `GET /rate` (the in-repo reference server uses `UUID.randomUUID()`), so the attacker needs the id from a side channel (shared screenshots/support tickets, a sending anchor in a SEP-31 corridor, logs, a predictable id scheme in a non-reference backend). No brute force is involved.

### Steps To Reproduce:
Local instance only, with SEP-10, SEP-38 and SEP-6 (or SEP-24) enabled and the reference business server (quick-run).

  1. As **victim** A (any keypair), obtain a SEP-10 JWT and request a firm quote:
     ```
     curl -s -X POST http://localhost:8080/sep38/quote -H "Authorization: Bearer $A_JWT" \
       -H 'Content-Type: application/json' \
       -d '{"sell_asset":"iso4217:USD","buy_asset":"stellar:USDC:<issuer>","sell_amount":"100","sell_delivery_method":"WIRE","context":"sep6"}'
     # -> {"id":"<Q>","price":"...","sell_amount":"100","buy_amount":"...","expires_at":"..."}
     ```
  2. Confirm the read path is protected: as **attacker** B (unrelated keypair, own SEP-10 JWT)
     `curl -s -w '\n%{http_code}\n' http://localhost:8080/sep38/quote/<Q> -H "Authorization: Bearer $B_JWT"` → `404 {"error":"quote not found"}`.
  3. As B, consume the quote anyway through the exchange endpoint (any of SEP-6 deposit-exchange, SEP-24 deposit/withdraw with `quote_id`, or SEP-31 POST):
     ```
     curl -s -w '\n%{http_code}\n' "http://localhost:8080/sep6/deposit-exchange?destination_asset=USDC&source_asset=iso4217:USD&amount=100&quote_id=<Q>&funding_method=WIRE" \
       -H "Authorization: Bearer $B_JWT"
     # -> 200 {"id":"<B_TXN>", ...}
     ```
  4. As A, try to use your own quote: the same request with `$A_JWT` now returns `400 {"error":"quote(id=<Q>) has already been used"}`.
  5. Via the Platform API (`GET /transactions/<B_TXN>`) observe `quote_id = Q`, `amount_in = 100`, `amount_out/fee` taken from A's quote; `GET /sep38/quote/<Q>` as A shows `transaction_id = <B_TXN>` (a transaction A cannot see).

### Supporting Material:
  * `core/src/main/java/org/stellar/anchor/util/ExchangeAmountsCalculator.java:110-192`
  * `core/src/main/java/org/stellar/anchor/sep31/Sep31Service.java:702-766`
  * `core/src/main/java/org/stellar/anchor/sep38/Sep38Service.java:283-286, 439-446, 549-552` (creator recorded and enforced on read; `client_id` passed to the rate callback)
  * Suggested fix: pass the `WebAuthJwt` into `validateQuoteAgainstRequestInfo` / `preValidateQuote` and reject when `creatorAccountId/creatorMemo/creatorMemoType` do not match the caller, mirroring `Sep38Service.getQuote`.

## Impact

### Summary:
Integrity/availability of other customers' quotes (authorization bypass). An authenticated wallet user can hijack a firm quote issued to another customer, obtaining that customer's negotiated price and fee for their own transaction, and simultaneously deny the legitimate customer the use of their quote (forcing re-quoting at a possibly worse rate). Requires knowledge of the quote id. CVSS v3.1: 5.4 (AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L).
