import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from disk_analyzer.cli import main
from disk_analyzer.identity import stat_identity, verify_image
from disk_analyzer.store import Store
from disk_analyzer.util import digest_file
from scripts.make_demo import WIF


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.image = self.root / "disk.img"
        self.image.write_bytes(b"\0" * 4096 + WIF.encode() + b"\n")
        self.case = self.root / "case"
        self.args = ["scan", str(self.image), "-o", str(self.case), "--carve", "off", "--allow-partial"]
        self.tools = patch("disk_analyzer.pipeline.available", return_value=None)
        self.doctor = patch("disk_analyzer.preflight.doctor", return_value={})
        self.tools.start()
        self.doctor.start()

    def tearDown(self):
        self.doctor.stop()
        self.tools.stop()
        self.temp.cleanup()

    def report(self):
        return json.loads((self.case / "findings.json").read_text())

    def test_quick_default_skips_digest_and_reuses_raw_checkpoint(self):
        with patch("disk_analyzer.identity.digest_file", side_effect=AssertionError("Full hash must not run")):
            self.assertEqual(main(self.args), 2)
            first = self.report()
            with patch("disk_analyzer.pipeline.scan_stream", side_effect=AssertionError("Completed raw scan must not rerun")):
                self.assertEqual(main(self.args + ["--resume"]), 2)
        self.assertIsNone(first["image"]["sha256"])
        self.assertEqual(first["image"]["hash_mode"], "quick")
        self.assertEqual(first["image"]["sha256_status"], "not-computed")
        self.assertTrue(any(f["kind"] == "wif_private_key" for f in first["findings"]))
        self.assertIn("Not computed", (self.case / "report.html").read_text())
        self.assertEqual(first["findings"], self.report()["findings"])

    def test_quick_resume_rejects_changed_metadata_without_reading_image(self):
        self.assertEqual(main(self.args), 2)
        self.image.write_bytes(self.image.read_bytes() + b"changed")
        with patch("disk_analyzer.identity.digest_file", side_effect=AssertionError("No digest in quick mode")), \
             patch("disk_analyzer.pipeline.scan_stream", side_effect=AssertionError("Must reject before scanning")):
            self.assertEqual(main(self.args + ["--resume"]), 1)
        self.assertEqual(self.report()["status"], "source-changed")

    def test_quick_identity_rejects_replacement_with_same_size_and_mtime(self):
        before = self.image.stat()
        previous = dict(stat_identity(before), sha256=None)
        replacement = self.root / "replacement.img"
        replacement.write_bytes(b"x" * before.st_size)
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        replacement.replace(self.image)
        with self.assertRaisesRegex(ValueError, "metadata changed"):
            verify_image(self.image, self.image.stat(), previous, "quick")

    def test_full_hash_checks_content_and_mode_is_saved(self):
        digest = hashlib.sha256(self.image.read_bytes()).hexdigest()
        with patch("disk_analyzer.identity.digest_file", wraps=digest_file) as calculate:
            self.assertEqual(main(self.args + ["--hash-mode", "full"]), 2)
            self.assertEqual(main(self.args + ["--resume"]), 2)
            self.assertEqual(calculate.call_count, 2)
        self.assertEqual(self.report()["image"]["sha256"], digest)
        self.assertEqual(self.report()["image"]["sha256_status"], "verified")
        before = self.image.stat()
        with self.image.open("r+b") as stream:
            stream.write(b"x")
        os.utime(self.image, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(main(self.args + ["--resume"]), 1)
        self.assertEqual(self.report()["image"]["sha256"], digest)

    def test_switch_modes_preserves_historical_hash_and_can_establish_baseline(self):
        self.assertEqual(main(self.args), 2)
        self.assertEqual(main(self.args + ["--resume", "--hash-mode", "full"]), 2)
        full = self.report()["image"]
        self.assertEqual(full["sha256_status"], "computed")
        with patch("disk_analyzer.identity.digest_file", side_effect=AssertionError("No digest in quick mode")):
            self.assertEqual(main(self.args + ["--resume", "--hash-mode", "quick"]), 2)
        quick = self.report()["image"]
        self.assertEqual(quick["sha256"], full["sha256"])
        self.assertEqual(quick["sha256_status"], "previously-recorded")

    def test_interrupted_initial_hash_resumes_in_quick_mode(self):
        with patch("disk_analyzer.identity.digest_file", side_effect=KeyboardInterrupt):
            self.assertEqual(main(self.args + ["--hash-mode", "full"]), 130)
        self.assertEqual(self.report()["status"], "interrupted")
        self.assertEqual(self.report()["image"]["sha256_status"], "pending")
        with patch("disk_analyzer.identity.digest_file", side_effect=AssertionError("No resumed full hash")):
            self.assertEqual(main(self.args + ["--resume", "--hash-mode", "quick"]), 2)
        self.assertTrue(any(f["kind"] == "wif_private_key" for f in self.report()["findings"]))

    def test_legacy_interrupted_hash_case_without_config_can_resume(self):
        self.case.mkdir()
        store = Store(self.case)
        store.put("status", "interrupted")
        store.close()
        self.assertEqual(main(self.args + ["--resume", "--hash-mode", "quick"]), 2)

    def test_case_with_results_but_missing_identity_is_rejected(self):
        self.case.mkdir()
        store = Store(self.case)
        store.stage("raw", "complete", progress=100)
        store.close()
        self.assertEqual(main(self.args + ["--resume"]), 1)

    def test_legacy_hash_case_can_resume_quickly(self):
        self.assertEqual(main(self.args + ["--hash-mode", "full"]), 2)
        store = Store(self.case)
        identity = store.get("image")
        store.put("image", {key: identity[key] for key in ("path", "size", "sha256", "mtime_ns")})
        config = store.get("config")
        del config["hash_mode"]
        store.put("config", config)
        store.close()
        with patch("disk_analyzer.identity.digest_file", side_effect=AssertionError("No legacy full hash")):
            self.assertEqual(main(self.args + ["--resume"]), 2)
        self.assertEqual(self.report()["image"]["hash_mode"], "quick")
        self.assertEqual(self.report()["image"]["sha256_status"], "previously-recorded")

    def test_source_changes_during_hashing_are_rejected(self):
        before = self.image.stat()
        def change(path, progress):
            value = digest_file(path)
            path.write_bytes(b"changed")
            return value
        with patch("disk_analyzer.identity.digest_file", side_effect=change):
            with self.assertRaisesRegex(ValueError, "changed during identity"):
                verify_image(self.image, before, None, "full")


if __name__ == "__main__":
    unittest.main()
