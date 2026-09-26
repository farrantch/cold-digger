import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from disk_analyzer.balances import bitcoin, ethereum, check_balances, endpoint
from disk_analyzer.crypto import backend
from disk_analyzer.detect import text_hits
from disk_analyzer.store import Store
from scripts.make_demo import SEED,WIF

BTC="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
ETH="0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"


class BalanceTests(unittest.TestCase):
    def test_no_network_without_explicit_opt_in(self):
        with patch("disk_analyzer.balances.request",side_effect=AssertionError("No request")):
            with self.assertRaisesRegex(ValueError,"allow-network"):
                check_balances(None,bitcoin_api="https://example.org/api")
        with self.assertRaises(ValueError):endpoint("http://example.org")
        self.assertEqual(endpoint("https://example.org/private-api-key?token=hidden")[1],"https://example.org")

    def test_bitcoin_confirmed_pending_and_activity_are_separate(self):
        response={"address":BTC,"chain_stats":{"funded_txo_sum":100,"spent_txo_sum":50,"tx_count":2},
                  "mempool_stats":{"funded_txo_sum":0,"spent_txo_sum":25,"tx_count":1}}
        with patch("disk_analyzer.balances.request",side_effect=["000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",response]) as request:
            result=bitcoin("https://example.org/api",BTC)
        self.assertEqual(result["balance_base_units"],"50")
        self.assertEqual(result["pending_delta_sats"],"-25")
        self.assertEqual(result["transaction_count"],3)
        self.assertNotIn(WIF,str(request.call_args))

    def test_wrong_bitcoin_network_cannot_produce_a_zero_balance(self):
        with patch("disk_analyzer.balances.request",return_value="testnet genesis"):
            with self.assertRaisesRegex(ValueError,"not Bitcoin mainnet"):
                bitcoin("https://example.org/api",BTC)

    def test_ethereum_checks_chain_and_does_not_claim_empty_wallet(self):
        values=[{"id":1,"result":"0x1"},{"id":1,"result":"0x0"},{"id":1,"result":"0x0"}]
        with patch("disk_analyzer.balances.request",side_effect=values) as request:
            result=ethereum("https://example.org",ETH)
        self.assertEqual(result["balance_base_units"],"0")
        self.assertIn("not an empty wallet",result["scope"])
        self.assertNotIn(SEED,str(request.call_args_list))
        with patch("disk_analyzer.balances.request",return_value={"id":1,"result":"0x89"}):
            with self.assertRaises(ValueError):ethereum("https://example.org",ETH)

    @unittest.skipUnless(backend()["available"],"Install crypto backend")
    def test_failed_provider_lookup_is_unknown_never_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(Path(tmp));store.finding(next(h for h in text_hits(BTC) if h.kind=="bitcoin_address"),{})
            try:
                with patch("disk_analyzer.balances.request",side_effect=OSError("offline")):
                    self.assertEqual(check_balances(store,bitcoin_api="https://example.org/api",allow_network=True),2)
                row=store.db.execute("SELECT status,data FROM balances").fetchone()
                self.assertEqual(row["status"],"error")
                self.assertNotIn("balance_base_units",json.loads(row["data"]))
            finally:store.close()
