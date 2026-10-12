# Proof of Concept

## Title
SEP-24 `GET /sep24/transactions` accepts a `paging_id` the caller does not own – cross-user transaction-id and timestamp oracle (anchor-platform ≤ 4.9.0)

## Description

### Summary:
`GET /sep24/transactions?paging_id=<id>` loads **any** SEP-24 transaction by id and uses its `started_at` as the listing cursor, without checking that the transaction belongs to the authenticated SEP-10 identity:

```java
// platform/src/main/java/org/stellar/anchor/platform/data/JdbcSep24TransactionStore.java:76-84
if (tr.getPagingId() != null) {
  Sep24Transaction txn = txnRepo.findOneByTransactionId(tr.getPagingId());
  if (txn != null) {
    olderThan = txn.getStartedAt();          // <- foreign transaction's timestamp is used
  } else {
    throw new SepValidationException(String.format("invalid paging_id field: %s", tr.getPagingId()));
  }
}
```

The identical defect in SEP-6 was reported and fixed as ANCHOR-1296 (commit `faec5e2`, "Reject a SEP-6 paging_id the caller does not own"), which added an `isVisibleTo(txn, accountId, accountMemo)` check in `JdbcSep6TransactionStore.java:71-81,123-126`. The SEP-24 store was not updated and still has the vulnerable logic, so the fixed SEP-6 behaviour and the unfixed SEP-24 behaviour now diverge in the same release.

Because the response differs between an id that exists (HTTP 200, the caller's own rows filtered by the foreign `started_at`) and one that does not (HTTP 400 `invalid paging_id field`), any authenticated wallet user gets:

1. an **existence oracle** for SEP-24 transaction ids belonging to other customers, and
2. a **timestamp oracle**: by comparing which of their own transactions are returned (`started_at < foreign.started_at`), the attacker can bracket when the victim's transaction was created, to arbitrary precision by first creating their own transactions at chosen times.

Transaction ids are random UUIDs, so the oracle requires an id obtained elsewhere (support ticket, shared screen, more_info_url, logs, SEP-31 counterparties, etc.); the program already accepted this exact class for SEP-6.

### Steps To Reproduce:
All steps on a local instance.

  1. Start the platform with SEP-10 and SEP-24 enabled (e.g. `quick-run/docker-compose.yaml`).
  2. As **victim** (keypair V): obtain a SEP-10 JWT and create a SEP-24 deposit:
     ```
     curl -s -X POST http://localhost:8080/sep24/transactions/deposit/interactive \
       -H "Authorization: Bearer $V_JWT" -H 'Content-Type: application/json' \
       -d '{"asset_code":"USDC"}'
     # -> {"type":"interactive_customer_info_needed","url":"...","id":"<VICTIM_TXN_ID>"}
     ```
  3. As **attacker** (keypair A, a completely unrelated account): obtain a SEP-10 JWT and create two deposits of your own, one *before* and one *after* step 2 (ids `A1`, `A2`).
  4. Query your own listing using the victim's id as cursor:
     ```
     curl -s -w '\n%{http_code}\n' "http://localhost:8080/sep24/transactions?asset_code=USDC&paging_id=<VICTIM_TXN_ID>" \
       -H "Authorization: Bearer $A_JWT"
     ```
     Result: `200` and the body lists only `A1` (started before the victim's transaction), proving the foreign `started_at` was consumed.
  5. Repeat with a random UUID:
     ```
     curl -s -w '\n%{http_code}\n' "http://localhost:8080/sep24/transactions?asset_code=USDC&paging_id=$(uuidgen)" \
       -H "Authorization: Bearer $A_JWT"
     # -> 400 {"error":"invalid paging_id field: ..."}
     ```
  6. Compare with the fixed SEP-6 endpoint: `GET /sep6/transactions?asset_code=USDC&paging_id=<VICTIM_SEP6_TXN_ID>` returns `400` for a foreign id.

### Supporting Material:
  * `platform/src/main/java/org/stellar/anchor/platform/data/JdbcSep24TransactionStore.java:76-84` (vulnerable)
  * `platform/src/main/java/org/stellar/anchor/platform/data/JdbcSep6TransactionStore.java:71-81,123-126` (fixed SEP-6 reference implementation, commit `faec5e2`, ANCHOR-1296)
  * Suggested fix: apply the same `isVisibleTo(txn, accountId, accountMemo)` check (account + memo equality) in the SEP-24 store, and keep the legacy `account:memo` fallback consistent.

## Impact

### Summary:
Confidentiality (information disclosure across customers). Any authenticated wallet user can confirm whether an arbitrary SEP-24 transaction id exists for *any* other customer and learn (to arbitrary precision) when that transaction was created, which is the exact issue SDF classified as a vulnerability and fixed for SEP-6 in ANCHOR-1296. CVSS v3.1: 4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N).
