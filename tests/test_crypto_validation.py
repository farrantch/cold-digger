import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from disk_analyzer.crypto import audit, backend, validate_material
from disk_analyzer.detect import Hit, text_hits
from disk_analyzer.store import Store
from disk_analyzer.triage import assessment, context_flags
from scripts.make_demo import SEED, WIF


@unittest.skipUnless(backend()["available"],"Install project dependencies for crypto vectors")
class CryptoTests(unittest.TestCase):
    def test_wif_public_addresses_and_ethereum_scalar_vector(self):
        result=validate_material("wif_private_key",WIF.encode())
        self.assertEqual(result["addresses"][0]["address"],"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        self.assertTrue(result["known_example"])
        eth=validate_material("contextual_hex_key",("0"*63+"1").encode())
        self.assertEqual(eth["addresses"][-1]["address"],"0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
        self.assertNotIn(WIF,json.dumps(result))

    def test_bip39_paths_include_receive_change_taproot_and_scope(self):
        result=validate_material("bip39_seed",SEED.encode(),1)
        self.assertEqual(len(result["addresses"]),9)
        self.assertEqual(result["addresses"][0]["address"],"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA")
        self.assertEqual(result["addresses"][-1]["address"],"0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
        self.assertTrue(any(a["path"]=="m/86'/0'/0'/1/0" for a in result["addresses"]))
        self.assertIn("Other passphrases",result["scope"])
        self.assertNotIn(SEED,json.dumps(result))

    def test_ethereum_case_preserved_and_bad_checksum_rejected(self):
        address="0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        hit=next(h for h in text_hits(address) if h.kind=="ethereum_address")
        self.assertEqual(hit.value.decode(),address)
        self.assertEqual(validate_material(hit.kind,hit.value)["status"],"valid")
        self.assertEqual(validate_material(hit.kind,address.lower().encode())["status"],"candidate")
        with self.assertRaises(ValueError):
            validate_material(hit.kind,address.replace("5aAe","5AAe").encode())

    def test_extended_public_key_matches_private_derivation(self):
        from bip_utils import Bip32Secp256k1
        root=Bip32Secp256k1.FromSeed(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        private=validate_material("extended_private_key",root.PrivateKey().ToExtended().encode(),1)
        public=validate_material("extended_public_key",root.PublicKey().ToExtended().encode(),1)
        self.assertEqual(private["addresses"],public["addresses"])
        self.assertNotIn(root.PrivateKey().ToExtended(),json.dumps(private))

    def test_keystore_metadata_is_not_authenticated_key_linkage(self):
        material={"version":3,"address":"7e5f4552091a69125d5dfcb7b8c2659029395bdf","crypto":{
            "cipher":"aes-128-ctr","ciphertext":"11"*32,"mac":"22"*32,"cipherparams":{"iv":"33"*16},
            "kdf":"scrypt","kdfparams":{"salt":"44"*32,"dklen":32,"n":16384,"r":8,"p":1}}}
        result=validate_material("ethereum_keystore",json.dumps(material).encode())
        self.assertEqual(result["status"],"encrypted")
        self.assertIn("unauthenticated",result["addresses"][0]["linkage"])
        material["crypto"]["kdfparams"]["n"]=3
        with self.assertRaises(ValueError):
            validate_material("ethereum_keystore",json.dumps(material).encode())

    def test_legacy_raw_material_read_is_bounded_and_cached_without_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);case=root/"case";case.mkdir();store=Store(case)
            address=b"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
            image=root/"source.img";image.write_bytes(b"<FTSText>"+address+b"</FTSText>")
            ident=store.finding(Hit("ethereum_address","Address",address.lower(),9,51),{"method":"raw","image_offset":9,"length":42})
            store.db.execute("DELETE FROM finding_material")
            try:
                result=audit(store,image,1)[ident]
                self.assertEqual(result["status"],"valid")
                self.assertIn("help-index markup",result["context_flags"])
                with patch("disk_analyzer.crypto.validate_material",side_effect=AssertionError("Do not erase/rederive without bytes")):
                    self.assertEqual(audit(store,None,1)[ident],result)
            finally:store.close()

    def test_backend_errors_do_not_leak_secret_exception_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(Path(tmp));ident=store.finding(next(h for h in text_hits(WIF) if h.secret),{})
            try:
                with patch("disk_analyzer.crypto.validate_material",side_effect=ValueError(WIF)):
                    result=audit(store)[ident]
                self.assertEqual(result["status"],"invalid")
                self.assertNotIn(WIF,json.dumps(result))
            finally:store.close()


class TriageTests(unittest.TestCase):
    def test_generic_paths_do_not_become_attention_findings(self):
        for kind in ("interesting_path","wallet_reference","recovery_reference","backup_reference"):
            f={"kind":kind,"sources":[],"id":"test"}
            self.assertEqual(assessment(f)["tier"],"background")

    def test_code_context_demotes_but_retains_candidates(self):
        flags=context_flags(b"secp192r1 " + b"0x"+b"a"*40+b" 0x"+b"b"*40+b" 0x"+b"c"*40)
        f={"kind":"ethereum_address","sources":[],"id":"test"}
        result=assessment(f,{"status":"valid","context_flags":flags})
        self.assertEqual(result["tier"],"background")
        self.assertIn("code",result["reason"])
