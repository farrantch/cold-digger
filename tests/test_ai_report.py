import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from disk_analyzer.ai import analyze, endpoint
from disk_analyzer.detect import Hit
from disk_analyzer.report import write_report
from disk_analyzer.store import Store
from scripts.make_demo import SEED, WIF


class AIReportTests(unittest.TestCase):
    def test_endpoint_restrictions(self):
        for url in ("https://example.com", "http://192.168.1.3:11434", "http://127.0.0.1.evil", "http://user@localhost", "http://localhost/redirect"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                endpoint(url)
        self.assertEqual(endpoint("http://localhost:11434"), "http://127.0.0.1:11434")
        self.assertEqual(endpoint("http://[::1]:11434"), "http://[::1]:11434")

    def test_ai_sees_redacted_metadata_and_rejects_invented_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp))
            try:
                ident = store.finding(Hit("seed", "Seed candidate", SEED.encode(), 0, 1, secret=True),
                                      {"path": "/notes/" + WIF, "method": "raw", "image_offset": 100})
                def fake_request(base, route, body=None, **kwargs):
                    if route == "/api/tags":
                        return {"models": [{"name": "local:latest", "digest": "test-digest"}]}
                    serialized = json.dumps(body)
                    self.assertNotIn(WIF, serialized)
                    self.assertNotIn(SEED, serialized)
                    claims = [{"type": "lead", "title": "Review seed context", "explanation": "Inspect the cited location", "evidence_ids": [ident]},
                              {"type": "inference", "title": "Invented", "explanation": "bad", "evidence_ids": ["Fmissing"]}]
                    return {"message": {"content": json.dumps({"claims": claims})}}
                with patch("disk_analyzer.ai.request", side_effect=fake_request):
                    self.assertEqual(analyze(store, "local"), 1)
                result = json.loads(store.db.execute("SELECT data FROM analyses").fetchone()[0])
                self.assertEqual(len(result["claims"]), 1)
                with self.assertRaises(ValueError):
                    analyze(store, "model:cloud")
            finally:
                store.close()

    def test_report_escapes_recovered_html_and_preserves_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp))
            try:
                store.put("image", {"sha256": "a" * 64})
                store.finding(Hit("wallet", "Wallet reference", b"wallet", 0, 1),
                              {"path": '<script>alert("bad")</script>'})
                write_report(store)
                text = (store.root / "report.html").read_text()
                self.assertNotIn('<script>alert("bad")</script>', text)
                self.assertIn("&lt;script&gt;", (store.root / "details.html").read_text())
                self.assertIn("a" * 64, text)
            finally:
                store.close()
