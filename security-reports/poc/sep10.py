import sys, requests
from stellar_sdk import Keypair, TransactionEnvelope, Network
BASE = sys.argv[1]; seed = sys.argv[2]; memo = sys.argv[3] if len(sys.argv) > 3 else None
kp = Keypair.from_secret(seed)
params = {"account": kp.public_key, "home_domain": "localhost:8080"}
if memo: params["memo"] = memo
r = requests.get(BASE + "/auth", params=params); r.raise_for_status()
env = TransactionEnvelope.from_xdr(r.json()["transaction"], Network.TESTNET_NETWORK_PASSPHRASE)
env.sign(kp)
r = requests.post(BASE + "/auth", json={"transaction": env.to_xdr()}); r.raise_for_status()
print(r.json()["token"])
