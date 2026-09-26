import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from disk_analyzer.cli import main
from disk_analyzer.util import case_lock
from scripts.make_demo import SEED, WIF


class RestartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.image = self.root / "disk.img"
        self.image.write_bytes(b"\0" * 4096 + SEED.encode() + b"\n")
        self.case = self.root / "case"
        self.args = ["scan", str(self.image), "--output", str(self.case), "--carve", "off", "--allow-partial"]
        self.tools = patch("disk_analyzer.pipeline.available", return_value=None)
        self.doctor = patch("disk_analyzer.preflight.doctor", return_value={})
        self.tools.start()
        self.doctor.start()
        self.assertEqual(main(self.args + ["--hash-mode", "full", "--max-file-bytes", "100", "--ocr"]), 2)
        self.old_report = (self.case / "findings.json").read_bytes()
        self.old_database = (self.case / "case.sqlite").read_bytes()
        self.assertTrue(any(f["kind"] == "bip39_seed" for f in json.loads(self.old_report)["findings"]))

    def tearDown(self):
        self.doctor.stop()
        self.tools.stop()
        self.temp.cleanup()

    def backups(self):
        return list(self.root.glob("case.backup-*"))

    def assert_preserved(self):
        self.assertEqual(self.backups(), [])
        self.assertEqual((self.case / "findings.json").read_bytes(), self.old_report)
        self.assertEqual((self.case / "case.sqlite").read_bytes(), self.old_database)

    def test_restart_archives_case_and_reprocesses_with_fresh_defaults(self):
        lock_inode = (self.case / ".lock").stat().st_ino
        (self.case / "artifacts" / "keep.bin").write_bytes(b"previous recovered evidence")
        self.image.write_bytes(b"\0" * 4096 + WIF.encode() + b"\n")
        source_digest = hashlib.sha256(self.image.read_bytes()).hexdigest()
        with patch("disk_analyzer.identity.digest_file", side_effect=AssertionError("Fresh default must be quick")):
            self.assertEqual(main(self.args + ["--restart"]), 2)
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), source_digest)
        backup, = self.backups()
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        self.assertEqual((backup / "findings.json").read_bytes(), self.old_report)
        self.assertEqual((backup / "case.sqlite").read_bytes(), self.old_database)
        self.assertEqual((backup / "artifacts/keep.bin").read_bytes(), b"previous recovered evidence")
        with sqlite3.connect(backup / "case.sqlite") as db:
            self.assertTrue(db.execute("SELECT 1 FROM findings").fetchone())
        self.assertFalse((self.case / "artifacts/keep.bin").exists())
        self.assertEqual((self.case / ".lock").stat().st_ino, lock_inode)
        current = json.loads((self.case / "findings.json").read_text())
        self.assertEqual(current["config"]["hash_mode"], "quick")
        self.assertEqual(current["config"]["max_file_bytes"], 4 * 1024**3)
        self.assertFalse(current["config"]["ocr"])
        kinds = {finding["kind"] for finding in current["findings"]}
        self.assertIn("wif_private_key", kinds)
        self.assertNotIn("bip39_seed", kinds)

    def test_repeated_restart_keeps_distinct_backups_and_accepts_overrides(self):
        with patch("disk_analyzer.util.time.strftime", return_value="20260101T000000Z"):
            self.assertEqual(main(self.args + ["--restart"]), 2)
            self.assertEqual(main(self.args + ["--restart", "--max-file-bytes", "8GiB", "--hash-mode", "full"]), 2)
        self.assertEqual(len(self.backups()), 2)
        self.assertTrue(all((backup / "case.sqlite").is_file() for backup in self.backups()))
        current = json.loads((self.case / "findings.json").read_text())
        self.assertEqual(current["config"]["max_file_bytes"], 8 * 1024**3)
        self.assertEqual(current["config"]["hash_mode"], "full")

    def test_restart_rejects_an_active_case_without_moving_files(self):
        with case_lock(self.case):
            self.assertEqual(main(self.args + ["--restart"]), 1)
        self.assert_preserved()

    def test_resume_and_restart_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit) as caught:
            main(self.args + ["--restart", "--resume"])
        self.assertEqual(caught.exception.code, 2)
        self.assert_preserved()

    def test_invalid_settings_do_not_archive_the_existing_case(self):
        self.assertEqual(main(self.args + ["--restart", "--max-files", "-1"]), 1)
        self.assert_preserved()

    def test_missing_tools_do_not_archive_the_existing_case(self):
        args = [arg for arg in self.args if arg != "--allow-partial"]
        with patch("disk_analyzer.pipeline.scan_stream", side_effect=AssertionError("Must not scan")):
            self.assertEqual(main(args + ["--restart"]), 1)
        self.assert_preserved()

    def test_invalid_source_does_not_archive_the_existing_case(self):
        self.image.write_bytes(b"")
        self.assertEqual(main(self.args + ["--restart"]), 1)
        self.assert_preserved()

    def test_image_inside_case_is_not_moved(self):
        image = self.case / "source.img"
        image.write_bytes(b"input image")
        self.assertEqual(main(["scan", str(image), "--output", str(self.case), "--restart"]), 1)
        self.assertEqual(image.read_bytes(), b"input image")
        self.assert_preserved()

    def test_unrelated_directory_and_missing_case_are_not_archived(self):
        unrelated = self.root / "unrelated"
        unrelated.mkdir()
        (unrelated / "keep.txt").write_text("keep")
        self.assertEqual(main(["scan", str(self.image), "--output", str(unrelated), "--restart"]), 1)
        self.assertEqual((unrelated / "keep.txt").read_text(), "keep")
        missing = self.root / "missing"
        self.assertEqual(main(["scan", str(self.image), "--output", str(missing), "--restart"]), 1)
        self.assertFalse(missing.exists())

    def test_archive_failure_and_interrupt_roll_back_moved_files(self):
        original_rename = Path.rename
        for error, code in ((OSError("simulated move failure"), 1), (KeyboardInterrupt(), 130)):
            with self.subTest(error=type(error).__name__):
                calls = 0
                def rename(path, target):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise error
                    return original_rename(path, target)
                with patch.object(Path, "rename", rename):
                    self.assertEqual(main(self.args + ["--restart"]), code)
                self.assert_preserved()


if __name__ == "__main__":
    unittest.main()
