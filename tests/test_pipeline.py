import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from disk_analyzer.cli import main
from disk_analyzer.pipeline import carve, parse_bodyfile
from scripts.make_demo import SEED, WIF, make_demo


class PipelineTests(unittest.TestCase):
    def test_bodyfile_unusual_filename_and_deleted(self):
        row = parse_bodyfile("0|/path|with|pipes (deleted)|12|r/rrw-r--r--|0|0|88|1|2|3|4\n", "p1")
        self.assertEqual(row["path"], "/path|with|pipes")
        self.assertEqual(row["deleted"], "deleted")
        self.assertEqual(json.loads(row["metadata"])["mtime"], 2)
        with self.assertRaises(ValueError):
            parse_bodyfile("invalid", "p1")

    def test_raw_only_report_and_resume_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "disk.img"
            image.write_bytes(b"\0" * 8190 + WIF.encode() + b"\n" + SEED.encode() + b"\n")
            before = hashlib.sha256(image.read_bytes()).hexdigest()
            output = root / "case"
            with patch("disk_analyzer.pipeline.available", return_value=None):
                result = main(["scan", str(image), "-o", str(output), "--carve", "off", "--chunk-size", "4KiB", "--hash-mode", "full", "--allow-partial"])
                self.assertEqual(result, 2)
                self.assertEqual(main(["scan", str(image), "-o", str(output), "--resume", "--allow-partial"]), 2)
            self.assertEqual(before, hashlib.sha256(image.read_bytes()).hexdigest())
            report = json.loads((output / "findings.json").read_text())
            self.assertEqual(report["image"]["sha256"], before)
            self.assertEqual(len([f for f in report["findings"] if f["kind"] == "wif_private_key"]), 1)
            for name in ("report.html", "findings.json", "inventory.csv"):
                public = (output / name).read_text()
                self.assertNotIn(WIF, public)
                self.assertNotIn(SEED, public)
            self.assertTrue(any(WIF.encode() in p.read_bytes() for p in (output / "private").glob("*.bin")))
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o700)
            image.write_bytes(image.read_bytes() + b"changed")
            self.assertEqual(main(["scan", str(image), "-o", str(output), "--resume", "--allow-partial"]), 1)

    def test_nonempty_output_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "disk.img"
            image.write_bytes(b"test data")
            case = root / "case"
            case.mkdir()
            (case / "report.html").write_text("original")
            self.assertEqual(main(["scan", str(image), "-o", str(case)]), 1)
            self.assertEqual((case / "report.html").read_text(), "original")

    @unittest.skipUnless(all(shutil.which(tool) for tool in ("fls", "icat", "fsstat", "mkfs.ext2", "debugfs", "photorec")),
                         "Real recovery integration requires sleuthkit, testdisk and e2fsprogs")
    def test_real_multipartition_deleted_and_carving(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = make_demo(root)
            before = hashlib.sha256(image.read_bytes()).hexdigest()
            output = root / "case"
            args = ["scan", str(image), "-o", str(output), "--max-output-bytes", "100MiB",
                    "--max-file-bytes", "32MiB", "--tool-timeout", "120"]
            # Reproduce a case scanned without dependencies, then install/retry.
            with patch("disk_analyzer.preflight.doctor", return_value={}), \
                 patch("disk_analyzer.pipeline.available", return_value=None):
                self.assertEqual(main(args + ["--allow-partial"]), 2)
            def carve_after_history(store, source, config):
                self.assertGreaterEqual(store.db.execute("SELECT count(*) FROM browser_history").fetchone()[0], 3)
                saved = json.loads((output / "browser-history.json").read_text())
                self.assertGreaterEqual(len(saved["records"]), 3)
                return carve(store, source, config)
            with patch("disk_analyzer.pipeline.scan_stream", side_effect=AssertionError("Must reuse completed raw scan")), \
                 patch("disk_analyzer.pipeline.carve", side_effect=carve_after_history):
                self.assertEqual(main(args + ["--resume"]), 0)
            self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(), before)
            data = json.loads((output / "findings.json").read_text())
            self.assertEqual(len(data["volumes"]), 2)
            self.assertEqual({v["filesystem_status"] for v in data["volumes"]}, {"complete"})
            self.assertGreaterEqual(data["browser_history"]["records"], 3)
            history = json.loads((output / "browser-history.json").read_text())["records"]
            self.assertEqual({r["family"] for r in history}, {"chromium", "firefox"})
            self.assertTrue(any(r["url"] == "https://electrum.org/download" for r in history))
            self.assertTrue(any(r["family"] == "firefox" and r["source"]["database_deleted"] == "deleted" for r in history))
            private = next(f for f in data["findings"] if f["kind"] == "wif_private_key")
            self.assertTrue(any(s.get("deleted") == "deleted" for s in private["sources"]))
            self.assertTrue(any(s.get("image_offset") == 19 * 1024**2 + len(b"PUBLIC TEST DATA ONLY\n") for s in private["sources"]))
            with sqlite3.connect(output / "case.sqlite") as db:
                files = db.execute("SELECT category,status,metadata FROM files").fetchall()
                large_history = db.execute("SELECT category,status,size FROM files WHERE path='/History'").fetchone()
                deleted_file = db.execute("SELECT deleted,status,artifact FROM files WHERE path='/forgotten.payload'").fetchone()
            self.assertEqual(deleted_file[:2], ("deleted", "exported"))
            self.assertEqual((output / deleted_file[2]).read_bytes(), (root / "forgotten.payload").read_bytes())
            self.assertEqual(large_history[:2], ("browser", "exported"))
            self.assertGreater(large_history[2], 2 * 1024**2)
            self.assertTrue(any(category == "media" and status == "exported" for category, status, _ in files))
            self.assertTrue(any('"origin": "photorec"' in metadata for _, _, metadata in files))
            carved = [json.loads(metadata) for _, _, metadata in files if '"origin": "photorec"' in metadata]
            self.assertTrue(all(item["extents"] for item in carved))
            self.assertEqual({v for item in carved for v in item["volumes"]}, {"p1", "p2"})
            self.assertEqual(main(["scan", str(image), "-o", str(output), "--resume"]), 0)

    @unittest.skipUnless(all(shutil.which(tool) for tool in ("fls", "icat", "fsstat", "mkfs.ext2", "debugfs")),
                         "Recovery limit test requires real forensic tools")
    def test_export_limit_is_reported_and_can_be_increased(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = make_demo(root)
            output = root / "case"
            self.assertEqual(main(["scan", str(image), "-o", str(output), "--carve", "off", "--max-file-bytes", "50", "--max-files", "5"]), 2)
            with sqlite3.connect(output / "case.sqlite") as db:
                self.assertGreater(db.execute("SELECT count(*) FROM files WHERE status='skipped-limit'").fetchone()[0], 0)
            self.assertEqual(main(["scan", str(image), "-o", str(output), "--resume", "--max-file-bytes", "32MiB"]), 2)
            with sqlite3.connect(output / "case.sqlite") as db:
                self.assertEqual(db.execute("SELECT count(*) FROM files WHERE status='skipped-limit'").fetchone()[0], 0)
                self.assertEqual(json.loads(db.execute("SELECT value FROM meta WHERE key='config'").fetchone()[0])["max_files"],0)
                self.assertEqual(db.execute("SELECT status FROM stages WHERE name='inventory:p1'").fetchone()[0],"complete")
