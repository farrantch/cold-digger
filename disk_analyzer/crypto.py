"""Local crypto validation using bip-utils; no network calls or spending operations."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from .detect import base58check, valid_bech32, MATERIAL_KINDS
from .triage import context_flags

VERSION = "1"
KINDS = MATERIAL_KINDS | {"wif_private_key", "extended_private_key", "bip39_seed", "contextual_hex_key",
                          "ethereum_keystore", "electrum_wallet", "encrypted_vault", "private_key_header"}


def backend():
    try:
        import bip_utils
        return {"available": True, "version": bip_utils.__version__}
    except ImportError:
        return {"available": False}


def address(chain, value, path="", linkage="derived from key"):
    return {"chain": chain, "address": value, "path": path, "linkage": linkage}


def bitcoin_addresses(pub, testnet=False, compressed=True, path=""):
    from bip_utils import P2PKHAddrEncoder, P2PKHPubKeyModes, P2SHAddrEncoder, P2WPKHAddrEncoder
    chain = "bitcoin-testnet" if testnet else "bitcoin"
    result = [address(chain, P2PKHAddrEncoder.EncodeKey(pub, net_ver=b"\x6f" if testnet else b"\0",
                pub_key_mode=P2PKHPubKeyModes.COMPRESSED if compressed else P2PKHPubKeyModes.UNCOMPRESSED), path + " · P2PKH")]
    if compressed:
        result += [address(chain, P2SHAddrEncoder.EncodeKey(pub, net_ver=b"\xc4" if testnet else b"\x05"), path + " · P2SH-P2WPKH"),
                   address(chain, P2WPKHAddrEncoder.EncodeKey(pub, hrp="tb" if testnet else "bc"), path + " · P2WPKH")]
    return result


def extended_addresses(value, count):
    from bip_utils import Bip32Secp256k1, Bip32KeyNetVersions
    payload = base58check(value)
    if payload is None or len(payload) != 78:
        raise ValueError("Invalid extended key")
    pairs = [(0x0488B21E, 0x0488ADE4, False), (0x043587CF, 0x04358394, True),
             (0x049D7CB2, 0x049D7878, False), (0x04B24746, 0x04B2430C, False),
             (0x044A5262, 0x044A4E28, True), (0x045F1CF6, 0x045F18BC, True)]
    version = int.from_bytes(payload[:4], "big")
    public, private, testnet = next(p for p in pairs if version in p[:2])
    root = Bip32Secp256k1.FromExtendedKey(value, Bip32KeyNetVersions(public.to_bytes(4,"big"), private.to_bytes(4,"big")))
    # The stored node's origin is not assumed. Try direct children and the usual
    # receiving/change branches relative to this node, retaining exact paths.
    result = bitcoin_addresses(root.PublicKey().RawCompressed().ToBytes(), testnet, path="stored node")
    for prefix in ("", "0/", "1/"):
        for i in range(count):
            path = prefix + str(i)
            child = root.DerivePath(path)
            result += bitcoin_addresses(child.PublicKey().RawCompressed().ToBytes(), testnet, path="relative/" + path)
    return result


def validate_material(kind, material, count=20):
    import bip_utils as b
    value = material.decode("utf-8",errors="replace") if kind == "private_key_header" else material.decode("utf-8")
    result = {"status": "valid", "summary": "Structure validated", "addresses": [], "backend": "bip-utils " + b.__version__}
    if kind == "private_key_header":
        if b"ENCRYPTED" in material:
            result.update(status="encrypted", summary="Encrypted private-key container; password required. Cryptocurrency use is not established")
        else:
            from Crypto.PublicKey import RSA, ECC
            try:
                key = RSA.import_key(material)
                if not key.has_private():
                    raise ValueError("Public key only")
                result.update(summary=f"RSA private key parsed ({key.size_in_bits()} bits); not a Bitcoin/Ethereum key",algorithm="RSA")
            except ValueError:
                try:
                    key = ECC.import_key(material)
                    if not key.has_private():
                        raise ValueError("Public key only")
                    result.update(summary="Elliptic-curve private key parsed; cryptocurrency use not established",algorithm=key.curve)
                except (ValueError,TypeError):
                    result.update(status="unsupported",summary="Private-key container is damaged or unsupported by the installed reader")
    elif kind == "bitcoin_address":
        payload = base58check(value)
        if not ((payload and len(payload) == 21 and payload[0] in (0,5,111,196)) or valid_bech32(value)):
            raise ValueError("Invalid Bitcoin address")
        chain = "bitcoin-regtest" if value.startswith("bcrt1") else "bitcoin-testnet" if value.lower().startswith("tb1") or (payload and payload[0] in (111,196)) else "bitcoin"
        result.update(summary="Bitcoin address checksum and structure valid; ownership unknown",
                      addresses=[address(chain, value, linkage="public address observed; no key linkage")])
    elif kind == "ethereum_address":
        mixed = value[2:] != value[2:].lower() and value[2:] != value[2:].upper()
        b.EthAddrDecoder.DecodeAddr(value, skip_chksum_enc=not mixed)
        result.update(status="valid" if mixed else "candidate", summary="Ethereum EIP-55 checksum valid" if mixed else "Ethereum address shape valid; no mixed-case checksum to verify",
                      addresses=[address("ethereum", value, linkage="public address observed; no key linkage")])
    elif kind in ("wif_private_key", "contextual_hex_key"):
        testnet, compressed = False, True
        if kind == "wif_private_key":
            raw = base58check(value)
            if raw is None:
                raise ValueError("Invalid WIF")
            testnet = raw[0] == 0xef
            secret, mode = b.WifDecoder.Decode(value, net_ver=b"\xef" if testnet else b"\x80")
            compressed = mode == b.WifPubKeyModes.COMPRESSED
        else:
            secret = bytes.fromhex(value)
        key = b.Secp256k1PrivateKey.FromBytes(secret)
        pub = key.PublicKey().RawCompressed().ToBytes()
        result["addresses"] = bitcoin_addresses(pub, testnet, compressed)
        if kind == "contextual_hex_key":
            result["addresses"].append(address("ethereum", b.EthAddrEncoder.EncodeKey(pub)))
        result.update(summary="Private scalar validated and public addresses derived locally",
                      known_example=int.from_bytes(secret, "big") == 1,
                      scope="Bitcoin address formats" if kind == "wif_private_key" else "Bitcoin/Ethereum address hypotheses; scalar does not identify its chain")
    elif kind == "bip39_seed":
        b.Bip39MnemonicValidator().Validate(value)
        seed = b.Bip39SeedGenerator(value).Generate("")
        plans = [(b.Bip44,b.Bip44Coins.BITCOIN,44), (b.Bip49,b.Bip49Coins.BITCOIN,49),
                 (b.Bip84,b.Bip84Coins.BITCOIN,84), (b.Bip86,b.Bip86Coins.BITCOIN,86)]
        for cls, coin, purpose in plans:
            account = cls.FromSeed(seed, coin).Purpose().Coin().Account(0)
            for change in (0,1):
                branch = account.Change(b.Bip44Changes(change))
                for i in range(count):
                    result["addresses"].append(address("bitcoin", branch.AddressIndex(i).PublicKey().ToAddress(), f"m/{purpose}'/0'/0'/{change}/{i}"))
        account = b.Bip44.FromSeed(seed, b.Bip44Coins.ETHEREUM).Purpose().Coin().Account(0).Change(b.Bip44Changes.CHAIN_EXT)
        for i in range(count):
            result["addresses"].append(address("ethereum", account.AddressIndex(i).PublicKey().ToAddress(), f"m/44'/60'/0'/0/{i}"))
        result.update(summary="BIP39 checksum valid; Bitcoin and Ethereum public addresses derived",
                      known_example=value == " ".join(["abandon"] * 11 + ["about"]),
                      scope=f"Empty BIP39 passphrase; account 0; first {count} addresses per listed branch. Other passphrases/accounts/paths/chains are not exhausted.")
    elif kind in ("extended_private_key", "extended_public_key"):
        result.update(addresses=extended_addresses(value, count), summary="Extended key checksum, structure and curve point validated; child addresses derived",
                      scope=f"Stored node plus {count} direct, receiving and change children relative to that node; its original derivation path is unknown")
    elif kind == "ethereum_keystore":
        data = json.loads(value)
        crypto = data.get("crypto", data.get("Crypto", {}))
        if data.get("version") != 3 or crypto.get("cipher") != "aes-128-ctr" or len(bytes.fromhex(crypto["ciphertext"])) != 32 or len(bytes.fromhex(crypto["mac"])) != 32 or len(bytes.fromhex(crypto["cipherparams"]["iv"])) != 16:
            raise ValueError("Invalid keystore structure")
        params = crypto["kdfparams"]
        if len(bytes.fromhex(params["salt"])) < 16 or params["dklen"] < 32:
            raise ValueError("Invalid KDF parameters")
        if crypto["kdf"] == "scrypt":
            n = params["n"]
            if not isinstance(n,int) or n <= 1 or n & (n-1) or params["r"] <= 0 or params["p"] <= 0:
                raise ValueError("Invalid scrypt parameters")
        elif crypto["kdf"] != "pbkdf2" or params.get("prf") != "hmac-sha256" or params.get("c",0) <= 0:
            raise ValueError("Unsupported KDF")
        if data.get("address"):
            addr = "0x" + data["address"].removeprefix("0x")
            b.EthAddrDecoder.DecodeAddr(addr, skip_chksum_enc=True)
            result["addresses"] = [address("ethereum",addr,linkage="unauthenticated keystore metadata; password required to prove linkage")]
        result.update(status="encrypted", summary="Ethereum V3 encryption parameters validated; password required for decryption and MAC verification")
    elif kind == "electrum_wallet":
        data = json.loads(value)
        if not isinstance(data.get("wallet_type"),str):
            raise ValueError("Invalid Electrum schema")
        key = data.get("keystore") or {}
        extended = key.get("xpub") if isinstance(key,dict) else None
        if extended:
            result["addresses"] = extended_addresses(extended,count)
            for item in result["addresses"]:
                item["linkage"] = "wallet public key; encrypted/private key linkage not verified"
        encrypted = bool(data.get("use_encryption") or data.get("seed_version") and not extended)
        result.update(status="encrypted" if encrypted else "candidate", summary="Electrum wallet schema recognized; available public key validated" if extended else "Electrum wallet schema recognized; no readable public key found",
                      scope="No password guessing or Electrum seed decryption; public derivation paths are relative to stored key")
    elif kind == "encrypted_vault":
        result.update(status="candidate", summary="Generic encrypted JSON container; application and key material not established")
    else:
        result.update(status="unsupported", summary="No validator for this candidate type")
    return result


def source_bytes(store, source, image=None, context=False):
    """Bounded reads only; never infer filesystem paths from recovered names."""
    relative = source.get("text_artifact") or source.get("artifact")
    offset = source.get("file_offset", source.get("text_offset"))
    path = None
    if relative and offset is not None:
        candidate = (store.root / relative).resolve()
        if store.root.resolve() in candidate.parents:
            path = candidate
    if path is None and image is not None and source.get("image_offset") is not None:
        path, offset = image, source["image_offset"]
    length = source.get("length",0)
    if path is None or not isinstance(offset,int) or not isinstance(length,int) or offset < 0 or not 0 < length <= 8*1024**2:
        return None
    margin = 8192 if context else 0
    try:
        with path.open("rb") as stream:
            stream.seek(max(0,offset-margin))
            return stream.read(min(length+margin*2, 65536) if context else length)
    except OSError:
        return None


def audit(store, image=None, count=20):
    if not 1 <= count <= 10000:
        raise ValueError("Address derivation count must be between 1 and 10000")
    info = backend()
    candidates = [f for f in store.findings() if f["kind"] in KINDS]
    for finding in candidates:
        previous = store.db.execute("SELECT data FROM crypto_assessments WHERE finding_id=?", (finding["id"],)).fetchone()
        row = store.db.execute("SELECT path FROM finding_material WHERE finding_id=?", (finding["id"],)).fetchone()
        relative = row[0] if row else finding["secret_path"]
        material = None
        if relative:
            path = (store.root / relative).resolve()
            if store.root.resolve() in path.parents and path.is_file() and path.stat().st_size <= 8*1024**2:
                material = path.read_bytes()
        flags = set(json.loads(previous[0]).get("context_flags",[])) if previous else set()
        for source in finding["sources"][:8]:
            context = source_bytes(store,source,image,context=True)
            if context:
                flags.update(context_flags(context))
                if finding["kind"] == "private_key_header" and material is None:
                    pem = re.search(rb"-----BEGIN ([A-Z ]*PRIVATE KEY(?: BLOCK)?)-----[\s\S]*?-----END \1-----",context)
                    if pem:
                        material = pem.group()
            if material is None:
                raw = source_bytes(store,source,image)
                if raw:
                    for encoding in ("ascii","utf-16le","utf-16be"):
                        try:
                            value = raw.decode(encoding).encode()
                        except (UnicodeError,ValueError):
                            continue
                        # Legacy Ethereum findings lowercased the fingerprint.
                        if hashlib.sha256(value).hexdigest() == finding["fingerprint"] or (finding["kind"] == "ethereum_address" and hashlib.sha256(value.lower()).hexdigest() == finding["fingerprint"]):
                            material = value
                            break
        overlap = False
        if material is None and previous and json.loads(previous[0]).get("status") != "unavailable":
            # A report-only refresh cannot reread legacy raw-image candidates.
            # Preserve the validated snapshot instead of erasing it.
            continue
        if finding["kind"] == "bip39_seed":
            for other in candidates:
                if other["id"] == finding["id"] or other["kind"] != "bip39_seed":
                    continue
                for a in finding["sources"]:
                    for b in other["sources"]:
                        field = "image_offset" if "image_offset" in a and "image_offset" in b else "file_offset"
                        same = field == "image_offset" or a.get("artifact") is not None and a.get("artifact") == b.get("artifact")
                        if same and field in a and field in b and max(a[field],b[field]) < min(a[field]+a.get("length",0),b[field]+b.get("length",0)):
                            overlap = True
        revision = hashlib.sha256(json.dumps([VERSION, info, hashlib.sha256(material).hexdigest() if material else None, count, sorted(flags), overlap]).encode()).hexdigest()
        old = store.db.execute("SELECT revision FROM crypto_assessments WHERE finding_id=?",(finding["id"],)).fetchone()
        if old and old[0] == revision:
            continue
        result = {"status":"unavailable", "summary":"Install project dependencies for automatic crypto validation", "addresses":[]}
        if info["available"] and material is not None:
            try:
                result = validate_material(finding["kind"],material,count)
            except Exception:
                # Third-party exceptions can contain secret values. Never publish them.
                result = {"status":"invalid", "summary":"Candidate failed structural/cryptographic validation", "addresses":[]}
        elif material is None:
            result.update(status="unavailable",summary="Candidate bytes unavailable; validate with the original image or recovered artifact")
        result.update(context_flags=sorted(flags),overlapping_seed=overlap)
        store.db.execute("INSERT OR REPLACE INTO crypto_assessments VALUES (?,?,?)",(finding["id"],revision,json.dumps(result)))
    store.db.commit()
    store.put("crypto_scope", {"address_count":count, "backend":info,
              "balance_status":"not checked automatically; use the explicit balances command", "offline":True})
    return {r["finding_id"]:json.loads(r["data"]) for r in store.db.execute("SELECT * FROM crypto_assessments")}
