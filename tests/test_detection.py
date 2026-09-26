import hashlib
from pathlib import Path
import tempfile
import unittest

from disk_analyzer.content import scan_stream
from disk_analyzer.detect import ORDER, base58check, redact, scan_bytes, structured_hits, valid_bech32, valid_mnemonic
from disk_analyzer.store import Store
from scripts.make_demo import SEED, WIF, base58


class DetectionTests(unittest.TestCase):
    def test_wif_checksum_and_scalar(self):
        hits = list(scan_bytes(WIF.encode()))
        self.assertEqual([h.kind for h in hits], ["wif_private_key"])
        self.assertTrue(hits[0].secret)
        broken = WIF[:-1] + ("1" if WIF[-1] != "1" else "2")
        self.assertIsNone(base58check(broken))
        for scalar in (0, ORDER):
            token = base58(b"\x80" + scalar.to_bytes(32, "big") + b"\x01")
            self.assertFalse(any(h.kind == "wif_private_key" for h in scan_bytes(token.encode())))

    def test_bip39(self):
        self.assertTrue(valid_mnemonic(SEED.split()))
        self.assertFalse(valid_mnemonic(["abandon"] * 12))
        hits = [h for h in scan_bytes(SEED.encode()) if h.kind == "bip39_seed"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, SEED.encode())
        self.assertEqual(list(scan_bytes(b"\0" * 10000)), [])

    def test_extended_private(self):
        payload = bytes.fromhex("0488ade4") + b"\0" * 9 + b"\x13" * 32 + b"\0" + (1).to_bytes(32, "big")
        token = base58(payload)
        self.assertTrue(any(h.kind == "extended_private_key" for h in scan_bytes(token.encode())))

    def test_utf16_offsets_and_chunk_boundaries(self):
        for encoding in ("utf-16le", "utf-16be"):
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                image = root / "image"
                image.write_bytes(b"\x99" * 4087 + WIF.encode(encoding) + b"\x99" * 200)
                case = root / "case"
                case.mkdir()
                store = Store(case)
                try:
                    scan_stream(store, image, {"method": "raw"}, raw=True, chunk_size=4096, stage="raw")
                    hits = [f for f in store.findings() if f["kind"] == "wif_private_key"]
                    self.assertEqual(len(hits), 1)
                    self.assertEqual(hits[0]["sources"][0]["image_offset"], 4087)
                    self.assertEqual(hits[0]["sources"][0]["deleted"], "unknown")
                    scan_stream(store, image, {"method": "raw"}, raw=True, chunk_size=4096, stage="raw")
                    self.assertEqual(store.db.execute("SELECT count(*) FROM occurrences").fetchone()[0], 1)
                finally:
                    store.close()

    def test_resume_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "image"
            image.write_bytes(b"\0" * 4090 + WIF.encode() + b"\0" * 6000)
            case = root / "case"
            case.mkdir()
            store = Store(case)
            try:
                scan_stream(store, image, {"method": "raw"}, raw=True, chunk_size=4096, stage="raw")
                store.stage("raw", "running", "Simulated interruption after first checkpoint", 4096)
                scan_stream(store, image, {"method": "raw"}, raw=True, chunk_size=4096, stage="raw")
                self.assertEqual(store.db.execute("SELECT count(*) FROM findings").fetchone()[0], 1)
            finally:
                store.close()

    def test_redaction_and_schema(self):
        self.assertNotIn(WIF, redact("Key " + WIF))
        self.assertNotIn(SEED, redact("Phrase " + SEED))
        self.assertNotIn("abandon " * 11, redact("abandon " * 12))
        hits = structured_hits(b'{"version":3,"crypto":{"cipher":"aes-128-ctr","ciphertext":"00","kdf":"scrypt","mac":"00"}}')
        self.assertEqual(hits[0].kind, "ethereum_keystore")
        self.assertFalse(structured_hits(b"not json"))

    def test_bech32_rejects_bad_checksum(self):
        self.assertTrue(valid_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))
        self.assertFalse(valid_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"))
