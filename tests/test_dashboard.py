import json
from pathlib import Path
import tempfile
import unittest
import importlib.util
from unittest.mock import patch

from disk_analyzer.dashboard import inventory_data, js_value, safe_asset
from disk_analyzer.store import Store
from disk_analyzer.pipeline import DEFAULTS, validate_config
from scripts.make_report_demo import make_report_demo
from disk_analyzer.cli import main


def data(path):
    return json.loads(path.read_text().split("=",1)[1].rstrip(";\n"))


class DashboardTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("PIL"),"Pillow required for image previews")
    def test_media_preparation_needs_no_source_image_or_recovery_scan(self):
        with tempfile.TemporaryDirectory() as tmp, patch("scripts.make_report_demo.shutil.which",return_value=None):
            root=Path(tmp);make_report_demo(root,1)
            before={p.name:p.read_bytes() for p in (root/"artifacts").iterdir()}
            with patch("disk_analyzer.pipeline.scan_stream",side_effect=AssertionError("No disk scan")), \
                 patch("disk_analyzer.content.inspect_zip",side_effect=AssertionError("No archive processing")):
                self.assertEqual(main(["media",str(root)]),0)
            self.assertEqual(len(list((root/"thumbnails").glob("*.jpg"))),57)
            self.assertEqual({p.name:p.read_bytes() for p in (root/"artifacts").iterdir()},before)

    def test_unlimited_count_is_default_and_negative_limit_is_rejected(self):
        self.assertEqual(DEFAULTS["max_files"],0)
        validate_config(DEFAULTS)
        with self.assertRaises(ValueError):validate_config({**DEFAULTS,"max_files":-1})

    def test_recovered_text_cannot_escape_scripts_or_create_asset_links(self):
        payload=js_value({"path":"</script><script>alert(1)</script>"})
        self.assertNotIn("<",payload)
        self.assertIn("</script>",json.loads(payload)["path"])
        for path in ("../../private/key.txt","https://example.org/track.png","artifacts/../../escape","javascript:alert(1)"):
            self.assertIsNone(safe_asset(path))

    def test_paginated_inventory_keeps_all_rows_and_separate_deleted_tree(self):
        with tempfile.TemporaryDirectory() as tmp, patch("scripts.make_report_demo.shutil.which",return_value=None):
            root=Path(tmp);make_report_demo(root,2100)
            manifest=data(root/"dashboard-data/inventory.js")
            self.assertEqual(manifest["chunk_count"],2)
            rows=[]
            for i in range(manifest["chunk_count"]):rows+=data(root/f"dashboard-data/inventory-{i}.js")
            self.assertEqual(len(rows),2159)
            self.assertEqual(len({r["id"] for r in rows}),len(rows))
            self.assertTrue(any(r["state"]=="deleted" and r["path"].startswith("/Documents/Archive/") for r in rows))
            self.assertTrue(any(r["state"]=="unknown" for r in rows))
            folder_names={f["name"] for f in manifest["folders"].values()}
            self.assertTrue({"Documents","Archive","Pictures","Album"}.issubset(folder_names))
            media=data(root/"dashboard-data/media.js")
            self.assertEqual(len(media),57)
            media_tree=data(root/"dashboard-data/media-folders.js")
            self.assertEqual(media_tree["volumes"],manifest["volumes"])
            self.assertNotIn("Documents",{f["name"] for f in media_tree["folders"].values()})
            self.assertTrue({"root"}.union(f["folder"] for f in media).issubset(media_tree["folders"]))
            for folder in media_tree["folders"].values():
                self.assertEqual(folder["parent"],manifest["folders"][folder["id"]]["parent"])
                if folder["parent"]:
                    self.assertIn(folder["id"],media_tree["folders"][folder["parent"]]["children"])
            report=json.loads((root/"findings.json").read_text())
            self.assertGreaterEqual(report["triage_summary"]["background"],97)
            self.assertIn("Needs attention",(root/"report.html").read_text())
            self.assertNotIn("<script>alert",(root/"dashboard-data/inventory-1.js").read_text())

    def test_empty_deleted_folders_do_not_inflate_file_counts_and_metadata_survives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = Store(root)
            try:
                store.volume({"id": "p1", "name": "Example volume", "filesystem": "ntfs"})
                for ident, path, state, mode, size in [
                    ("directory", "/Empty", "deleted", "d/drwxr-xr-x", 0),
                    ("file", "\\Pictures\\photo.jpg", "deleted", "r/rrw-r--r--", 4096),
                    ("replacement", "/Empty/new.bin", "reallocated", "r/rrw-r--r--", 4 * 1024**3),
                ]:
                    store.file({"id": ident, "path": path, "volume": "p1", "inode": "42-128-1",
                                "size": size, "deleted": state, "category": "other", "priority": 5,
                                "metadata": json.dumps({"mode": mode, "mtime": 1688169600, "crtime": 1609459200})})
                store.file_status("replacement", "partial", "Only part recovered", artifact="artifacts/" + "a" * 64 + ".bin", sha256="a" * 64)
                directory = root / "dashboard-data"
                directory.mkdir()
                manifest, _ = inventory_data(store, directory)
                self.assertEqual(manifest["counts"], {"deleted": 1, "reallocated": 1})
                self.assertEqual(manifest["folders"]["root"]["counts"], manifest["counts"])
                empty = next(f for f in manifest["folders"].values() if f["name"] == "Empty")
                self.assertEqual(empty["dir_counts"], {"deleted": 1})
                self.assertEqual(empty["counts"], {"reallocated": 1})
                rows = data(directory / "inventory-0.js")
                self.assertEqual(len(rows), 2)
                replacement = next(f for f in rows if f["id"] == "replacement")
                self.assertEqual(replacement["size"], 4294967296)
                self.assertEqual(replacement["modified"], 1688169600)
                self.assertEqual(replacement["created"], 1609459200)
                self.assertEqual(replacement["status"], "partial")
                self.assertEqual(replacement["sha256"], "a" * 64)
                self.assertEqual(replacement["inode"], "42-128-1")
                self.assertEqual(manifest["volumes"]["p1"]["name"], "Example volume")
            finally:
                store.close()
