import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from disk_analyzer.cli import main
from disk_analyzer.pipeline import DEFAULTS
from disk_analyzer.preflight import check_dependencies


READY = {name: {"available": True} for name in
         ("fsstat", "fls", "icat", "photorec", "pymsiecf", "pyesedb", "bip_utils")}


class PreflightTests(unittest.TestCase):
    def test_missing_tools_stop_before_hashing_scanning_or_case_database_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "disk.img"
            image.write_bytes(b"image bytes")
            case = root / "case"
            error = io.StringIO()
            with patch("disk_analyzer.preflight.doctor", return_value={}), \
                 patch("disk_analyzer.pipeline.verify_image", side_effect=AssertionError("Must not hash")), \
                 patch("disk_analyzer.pipeline.scan_stream", side_effect=AssertionError("Must not scan")), \
                 contextlib.redirect_stderr(error):
                self.assertEqual(main(["scan", str(image), "-o", str(case), "--hash-mode", "full"]), 1)
            self.assertFalse((case / "case.sqlite").exists())
            for package in ("sleuthkit", "testdisk", "python3-libmsiecf", "python3-libesedb"):
                self.assertIn(package, error.getvalue())

    def test_partial_opt_in_is_not_saved_and_failed_resume_preserves_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "disk.img"
            image.write_bytes(b"image bytes")
            case = root / "case"
            args = ["scan", str(image), "-o", str(case)]
            with patch("disk_analyzer.preflight.doctor", return_value={}), \
                 patch("disk_analyzer.pipeline.available", return_value=None):
                self.assertEqual(main(args + ["--allow-partial"]), 2)
                report = (case / "findings.json").read_bytes()
                database = (case / "case.sqlite").read_bytes()
                data = json.loads(report)
                self.assertNotIn("allow_partial", data["config"])
                history = next(s for s in data["stages"] if s["name"] == "browser_history")
                self.assertEqual(history["status"], "partial")
                self.assertIn("Filesystem recovery is unavailable", history["detail"])
                self.assertEqual(main(args + ["--resume"]), 1)
                self.assertEqual((case / "findings.json").read_bytes(), report)
                self.assertEqual((case / "case.sqlite").read_bytes(), database)

    def test_ie_readers_are_required_even_before_history_databases_are_found(self):
        for name in ("pymsiecf", "pyesedb"):
            with self.subTest(reader=name), patch("disk_analyzer.preflight.doctor", return_value={
                    key: value for key, value in READY.items() if key != name}):
                with self.assertRaisesRegex(ValueError, name):
                    check_dependencies(DEFAULTS)

    def test_only_enabled_optional_passes_require_their_tools(self):
        with patch("disk_analyzer.preflight.doctor", return_value=READY):
            self.assertEqual(check_dependencies(DEFAULTS), READY)
            for option, tool in (("ocr", "tesseract"), ("bulk", "bulk_extractor")):
                with self.subTest(option=option), self.assertRaisesRegex(ValueError, tool):
                    check_dependencies({**DEFAULTS, option: True})
        without_photorec = {key: value for key, value in READY.items() if key != "photorec"}
        with patch("disk_analyzer.preflight.doctor", return_value=without_photorec):
            check_dependencies({**DEFAULTS, "carve": "off"})
            for mode in ("auto", "on"):
                with self.subTest(carve=mode), self.assertRaisesRegex(ValueError, "photorec"):
                    check_dependencies({**DEFAULTS, "carve": mode})

    def test_resume_checks_saved_options_before_touching_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "disk.img"
            image.write_bytes(b"image bytes")
            case = root / "case"
            args = ["scan", str(image), "-o", str(case)]
            with patch("disk_analyzer.preflight.doctor", return_value={}), \
                 patch("disk_analyzer.pipeline.available", return_value=None):
                self.assertEqual(main(args + ["--allow-partial", "--bulk"]), 2)
            before = (case / "case.sqlite").read_bytes()
            error = io.StringIO()
            with patch("disk_analyzer.preflight.doctor", return_value=READY), contextlib.redirect_stderr(error):
                self.assertEqual(main(args + ["--resume"]), 1)
            self.assertIn("bulk_extractor", error.getvalue())
            self.assertEqual((case / "case.sqlite").read_bytes(), before)
