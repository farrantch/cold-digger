"""Explicit opt-in public-address lookups. No keys, seeds, or wallet files leave the case."""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import ipaddress
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from .crypto import audit
from .detect import base58check, valid_bech32
from .triage import assessment
from .util import log


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def endpoint(value):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http","https") or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Balance endpoint must be HTTP(S), without userinfo or a fragment")
    if parsed.scheme == "http":
        try:
            private = ipaddress.ip_address(parsed.hostname).is_private
        except ValueError:
            private = parsed.hostname == "localhost"
        if not private:
            raise ValueError("Use HTTPS for public balance providers; HTTP is limited to local/private IP endpoints")
    # Deliberately omit paths/query strings, which may contain provider API keys.
    return value.rstrip("/"), f"{parsed.scheme}://{parsed.netloc}"


def request(url, body=None, *, plain=False):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    req = urllib.request.Request(url,data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type":"application/json","User-Agent":"cold-digger/0.1"})
    with opener.open(req,timeout=20) as response:
        payload = response.read(1024**2+1)
    if len(payload)>1024**2:
        raise ValueError("Balance response too large")
    return payload.decode("ascii").strip() if plain else json.loads(payload)


def integer(value):
    if type(value) is not int or value < 0:
        raise ValueError("Invalid provider count")
    return value


def rpc(url,method,params):
    data = request(url,{"jsonrpc":"2.0","id":1,"method":method,"params":params})
    if data.get("error") or data.get("id")!=1 or not re.fullmatch(r"0x[0-9a-fA-F]+",str(data.get("result",""))):
        raise ValueError("Invalid JSON-RPC response")
    return int(data["result"],16)


def bitcoin(url,address):
    payload=base58check(address)
    if not ((payload and len(payload)==21 and payload[0] in (0,5)) or (address.lower().startswith("bc1") and valid_bech32(address))):
        raise ValueError("Expected Bitcoin mainnet public address")
    genesis=request(url+"/block-height/0",plain=True)
    if genesis!="000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f":
        raise ValueError("Esplora endpoint is not Bitcoin mainnet")
    data=request(url+"/address/"+urllib.parse.quote(address,safe=""))
    if data.get("address")!=address:
        raise ValueError("Provider returned another address")
    chain,mempool=data["chain_stats"],data["mempool_stats"]
    amount=integer(chain["funded_txo_sum"])-integer(chain["spent_txo_sum"])
    if amount<0:
        raise ValueError("Invalid confirmed balance")
    pending=integer(mempool["funded_txo_sum"])-integer(mempool["spent_txo_sum"])
    tx=integer(chain["tx_count"])+integer(mempool["tx_count"])
    return {"balance_base_units":str(amount),"balance_display":str(Decimal(amount)/Decimal(10**8))+" BTC",
            "pending_delta_sats":str(pending),"transaction_count":tx,"activity":"transaction history found" if tx else "no transactions reported for this address",
            "scope":"Bitcoin mainnet at provider snapshot; confirmed balance, pending delta separate. Other addresses/chains not ruled out."}


def ethereum(url,address):
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}",address):
        raise ValueError("Expected Ethereum public address")
    if rpc(url,"eth_chainId",[]) != 1:
        raise ValueError("RPC is not Ethereum mainnet")
    amount=rpc(url,"eth_getBalance",[address,"latest"])
    nonce=rpc(url,"eth_getTransactionCount",[address,"latest"])
    return {"balance_base_units":str(amount),"balance_display":str(Decimal(amount)/Decimal(10**18))+" ETH",
            "outgoing_transaction_count":nonce,"activity":"outgoing transactions found" if nonce else "no outgoing transactions reported; incoming/token history unknown",
            "scope":"Ethereum mainnet native ETH only; ERC-20/NFT assets, L2s, other chains and incoming history are not queried. Zero ETH is not an empty wallet."}


def check_balances(store, *, bitcoin_api=None, ethereum_rpc=None, allow_network=False, include_background=False):
    if not allow_network:
        raise ValueError("Balance lookups require --allow-network; only public addresses are sent to your chosen provider")
    supplied={k:endpoint(v) for k,v in (("bitcoin",bitcoin_api),("ethereum",ethereum_rpc)) if v}
    if not supplied:
        raise ValueError("Specify --bitcoin-api and/or --ethereum-rpc; no provider is contacted by default")
    audits=audit(store,count=store.get("crypto_scope",{}).get("address_count",20))
    targets=set()
    for f in store.findings():
        validation=audits.get(f["id"],{})
        if not include_background and assessment(f,validation)["tier"]=="background":
            continue
        for item in validation.get("addresses",[]):
            if item["chain"] in supplied:
                targets.add((item["chain"],item["address"].lower() if item["chain"]=="ethereum" else item["address"]))
    log(f"Checking {len(targets)} public addresses with the selected providers; private keys and seed values stay local")
    errors=0
    for i,(chain,address) in enumerate(sorted(targets)):
        url,label=supplied[chain]
        try:
            result=(bitcoin if chain=="bitcoin" else ethereum)(url,address)
            status="ok"
        except (OSError,ValueError,KeyError,TypeError):
            status="error";errors+=1
            result={"scope":"Lookup failed; balance remains unknown"}
        checked=datetime.now(timezone.utc).isoformat()
        store.db.execute("INSERT OR REPLACE INTO balances VALUES (?,?,?,?,?,?)",(chain,address,label,checked,status,json.dumps(result)))
        store.db.commit()
        if i%10==0:
            log(f"Balances: {i+1}/{len(targets)} checked; {errors} errors")
        if i+1<len(targets):
            time.sleep(0.5)
    store.put("balance_scope",{"addresses_checked":len(targets),"errors":errors,"include_background":include_background,
              "providers":{chain:label for chain,(_,label) in supplied.items()},"tokens_checked":False})
    return 2 if errors else 0
