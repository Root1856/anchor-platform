# Proof of Concept

## Title
SEP-24 withdrawal routing memo is taken from the wallet request, letting any user reserve another user's memo and block or capture their withdrawal

(147 characters)

## Description

### Summary:
Stellar Anchor Platform (release 4.9.0 and current `develop`) builds the on-chain routing memo of a SEP-24 withdrawal from the `memo` and `memo_type` fields of the wallet's `POST /sep24/transactions/withdraw/interactive` request. SEP-24 defines those two fields as deprecated user-identification fields ("originally intended to differentiate users of the same Stellar account"), not as the payment memo. The platform stores them unchanged and, when the anchor later calls `request_onchain_funds`, the default deposit-info generator reuses the stored value as `withdraw_memo` instead of generating a random memo:

* `core/src/main/java/org/stellar/anchor/sep24/Sep24Service.java` lines 190 to 212: `makeMemo(withdrawRequest.get("memo"), withdrawRequest.get("memo_type"))` is stored on the transaction. The value is never compared with the token identity and never checked for uniqueness.
* `platform/src/main/java/org/stellar/anchor/platform/service/Sep24DepositInfoSelfGenerator.java` lines 10 to 16: `if ("id".equalsIgnoreCase(txn.getMemoType()) && txn.getMemo() != null) return new SepDepositInfo(txn.getToAccount(), txn.getMemo());` (the SEP-6 twin always calls `generateMemoId()`, a 63-bit SecureRandom value).
* `platform/src/main/java/org/stellar/anchor/platform/rpc/RequestOnchainFundsHandler.java` lines 319 to 324 copy the generated value into `withdraw_anchor_account` and `memo`, and line 96 maps the unique-index violation added by migration `V28__memo_uniqueness_pending_transfer.sql` to the error `memo_in_use`.
* `platform/src/main/java/org/stellar/anchor/platform/observer/stellar/DefaultPaymentListener.java` lines 219 to 247 route incoming Stellar payments purely by `(withdraw_anchor_account, memo, status = pending_user_transfer_start)`; the sender of the payment is not compared.

Because the memo is attacker-chosen and shared across all users of the anchor, any authenticated wallet user can reserve a memo value that belongs to another user. The uniqueness index then enforces the attacker's reservation against the victim:

1. Denial of withdrawal. While the attacker's withdrawal is `pending_user_transfer_start` with memo M, every `request_onchain_funds` for any other user's withdrawal carrying memo M fails with `memo_in_use`. The attacker can keep the reservation alive indefinitely by creating a new withdrawal whenever the previous one expires. Custodial wallets that still send the deprecated field use low-entropy, predictable values (the user's own sub-account memo), so specific victims can be targeted.
2. Capture of a late payment. If the victim's withdrawal with memo M was already `pending_user_transfer_start` and then expires or errors before the user pays, the attacker can immediately create a withdrawal with the same memo M. A payment the victim's wallet sends afterwards is matched to the attacker's transaction (the observer matches only account plus memo, not the payer), so the anchor credits the attacker and pays the attacker's off-chain payout with the victim's on-chain funds.

Both effects need only an ordinary SEP-10 session for the attacker's own account and knowledge of the victim's memo value. No wallet signing key, no custodial key and no business-server access is required.

### Steps To Reproduce:
Performed on a local build of 4.9.0 only (local PostgreSQL, SEP server on port 8080, Platform server on port 8085 with the default `platform_api.auth.type: none`, `sep24.deposit_info_generator_type: self`). The Platform API calls below represent what the anchor's business server does after the interactive flow; no public network was used.

1. Build and start the stack:
   ```
   ./gradlew :service-runner:bootJar -x test
   java -jar service-runner/build/libs/anchor-platform-runner-4.9.0.jar --sep-server --platform-server
   ```
2. Obtain SEP-10 tokens for two unrelated, freshly generated keypairs V (victim) and A (attacker) with `GET /auth`, sign the challenge, `POST /auth`.
3. As the victim, create a withdrawal that carries the deprecated identification memo (this is what a custodial wallet sends for sub-account 1001):
   ```
   POST /sep24/transactions/withdraw/interactive
   Authorization: Bearer <V token>
   {"asset_code":"USDC","amount":"5","memo":"1001","memo_type":"id"}
   ```
4. As the attacker, create a withdrawal with the same memo value from a completely different account:
   ```
   POST /sep24/transactions/withdraw/interactive
   Authorization: Bearer <A token>
   {"asset_code":"USDC","amount":"5","memo":"1001","memo_type":"id"}
   ```
5. Let the anchor advance the attacker's transaction first (the attacker completes the interactive step first):
   ```
   POST http://localhost:8085/
   [{"jsonrpc":"2.0","id":1,"method":"request_onchain_funds","params":{"transaction_id":"<A txn>",
     "amount_in":{"amount":"5","asset":"stellar:USDC:GDQOE23CFSUMSVQK4Y5JHPPYK73VYCNHZHA7ENKCV37P6SUEO6XQBKPP"},
     "amount_out":{"amount":"4.9","asset":"iso4217:USD"},
     "fee_details":{"total":"0.1","asset":"stellar:USDC:GDQOE23CFSUMSVQK4Y5JHPPYK73VYCNHZHA7ENKCV37P6SUEO6XQBKPP"},
     "amount_expected":{"amount":"5"}}}]
   ```
6. Let the anchor advance the victim's transaction with the same call for `<V txn>`.
7. Read both transactions with `GET /sep24/transaction?id=...` using each owner's token.

### Results observed:
```
victim  G = GD3QGJQ57BF5EL7554GLP2M7ON57ODKFIITUBLMAAVPK7SXWBEWKPODB
attacker G = GCNZWJOBGNE73FZZWU6BA7JUO7LJRK4DIO3K54ZOZA3OFNX6CQBYB7G7
victim  POST withdraw memo=1001 -> 200 02134666-4b7d-4c91-a6a3-cf924e55f232
attacker POST withdraw memo=1001 -> 200 3aaf26f6-7784-49d3-ba2d-842e3b380886
anchor request_onchain_funds(attacker txn) -> 200 {"result":{"id":"3aaf26f6-...","sep":"24","kind":"withdrawal","status":"pending_user_transfer_start", ...}}
attacker txn now: status=pending_user_transfer_start, withdraw_anchor_account=GBN4NNCDGJO4XW4KQU3CBIESUJWFVBUZPOKUZHT7W7WRB7CWOA7BXVQF, withdraw_memo=1001, withdraw_memo_type=id
anchor request_onchain_funds(victim txn)   -> 200 {"error":{"id":"02134666-...","code":-32602,"message":"memo_in_use: the requested memo and destination account are already assigned to a pending transaction"}}
victim txn now: status=incomplete, withdraw_anchor_account=None, withdraw_memo=1001, withdraw_memo_type=id
```
The attacker's transaction holds the anchor's distribution account with memo 1001; the victim's transaction cannot be advanced for as long as that reservation exists. Reversing the order of steps 5 and 6 (victim first, then the victim's transaction expires) produces the capture case described above, because the attacker's later `request_onchain_funds` succeeds once the victim's row leaves `pending_user_transfer_start`, and the payment observer then routes any payment with memo 1001 to the attacker's transaction.

### Confirmation from public sources:
* SEP-24 specification (stellar/stellar-protocol, ecosystem/sep-0024.md), withdraw request fields: `memo` is "deprecated" and "was originally intended to differentiate users of the same Stellar account"; "the anchor should use the sub value included in the decoded SEP-10 JWT instead"; `memo_type` is "deprecated because memos used to identify users of the same Stellar account should always be of type of id". The payment memo is communicated by the anchor through the `withdraw_memo` transaction field. The platform conflates the two.
* stellar/anchor-platform pull request 1942 ("[ANCHOR-1939]: add ambiguous routing safety"): adds the `uq_sep24_pending_memo` unique index and the `memo_in_use` error; a reviewer notes in that discussion that duplicate routing tuples "can still be created via the memo_type=id path". The index stops two pending rows from sharing a memo but does not stop a third party from being the one who holds it.
* stellar/anchor-platform `develop` branch, `platform/src/main/java/org/stellar/anchor/platform/service/Sep24DepositInfoSelfGenerator.java`, shows the request memo being returned as the deposit info when `memo_type` is `id`.

### Suggested fix:
Never use the wallet-supplied identification memo as the routing memo: always call `generateMemoId()` in `Sep24DepositInfoSelfGenerator` (as `Sep6DepositInfoSelfGenerator` does) and keep the request memo only as user metadata; alternatively require the request memo to equal the SEP-10 token memo and scope the uniqueness check per authenticated identity.

## Impact

### Summary:
Integrity and availability of other customers' withdrawals. Any authenticated wallet user of the anchor can reserve the routing memo of a targeted user (predictable for custodial wallets that send the deprecated identification memo), preventing that user's withdrawal from ever reaching the payable state, and, when the victim's transaction expires or errors before payment, can have the victim's subsequent on-chain payment credited to the attacker's withdrawal so that the anchor pays the attacker's off-chain destination with the victim's funds. CVSS v3.1 base 6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L) for the reservation case; 7.1 (I:H) when the capture case applies.
