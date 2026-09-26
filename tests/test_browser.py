from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from disk_analyzer.browser import crypto_domain, domain, extract_history, history_name, timestamp
from disk_analyzer.cli import main
from disk_analyzer.content import classify
from disk_analyzer.report import write_report
from disk_analyzer.store import Store
from scripts.make_demo import WIF

UNIX_TIME = 1704164645123456  # 2024-01-02 03:04:05.123456 UTC
CHROME_TIME = UNIX_TIME + 11644473600000000


def chromium(path, *, wal=False):
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER, from_visit INTEGER, originator_cache_guid TEXT);
        CREATE TABLE visit_source(id INTEGER PRIMARY KEY, source INTEGER);
    """)
    db.commit()
    if wal:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA wal_autocheckpoint=0")
    db.execute("INSERT INTO urls VALUES (1,?,?,3,?)", ("https://electrum.org/download?secret=private-query#private-fragment", "Electrum wallet", CHROME_TIME))
    db.executemany("INSERT INTO visits VALUES (?,?,?,?,?,?)", [(11, 1, CHROME_TIME, 1, 0, ""),
                                                              (12, 1, CHROME_TIME + 1000000, 0, 11, "remote-device")])
    db.execute("INSERT INTO visit_source VALUES (12,0)")
    db.commit()
    return db


def firefox(path):
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
        CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, from_visit INTEGER);
        INSERT INTO moz_places VALUES(2,'https://bookmark-only.example/','A bookmark',0,NULL);
    """)
    db.execute("INSERT INTO moz_places VALUES (1,?,?,2,?)", ("https://example.org/", "Example", UNIX_TIME))
    db.execute("INSERT INTO moz_historyvisits VALUES (21,1,?,1,0)", (UNIX_TIME,))
    db.commit()
    db.close()


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "case").mkdir()
        self.store = Store(self.root / "case")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def add(self, path, original, ident="Etest", deleted="allocated", status="exported"):
        data = path.read_bytes()
        target = "artifacts/" + ident + ".bin"
        (self.store.root / target).write_bytes(data)
        category, priority = classify(original, deleted)
        self.store.file({"id": ident, "volume": "p1", "inode": ident, "path": original, "size": len(data),
                         "deleted": deleted, "category": category, "priority": priority, "metadata": "{}"})
        self.store.file_status(ident, status, artifact=target, sha256=hashlib.sha256(data).hexdigest())
        return self.store.root / target

    def records(self):
        return list(self.store.db.execute("SELECT * FROM browser_history ORDER BY id"))

    def test_chromium_visits_timestamps_and_crypto_leads(self):
        path = self.root / "History"
        chromium(path).close()
        exported = self.add(path, "/Users/me/AppData/Local/Google/Chrome/User Data/Default/History")
        before = exported.read_bytes()
        self.assertEqual(extract_history(self.store), 0)
        rows = self.records()
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["browser"] for r in rows}, {"Chrome"})
        first = next(r for r in rows if r["record_id"] == "11")
        self.assertEqual(first["visited_utc"], "2024-01-02T03:04:05.123456Z")
        self.assertTrue(any("Remote/synced" in r["origin"] for r in rows))
        self.assertEqual(before, exported.read_bytes())
        self.assertFalse(Path(str(exported) + "-wal").exists())
        leads = [f for f in self.store.findings() if f["kind"] == "crypto_browser_domain"]
        self.assertEqual(len(leads), 1)
        self.assertEqual(len(leads[0]["sources"]), 2)
        self.assertEqual(extract_history(self.store), 0)
        self.assertEqual(len(self.records()), 2)
        self.assertEqual(len(next(f for f in self.store.findings() if f["kind"] == "crypto_browser_domain")["sources"]), 2)

    def test_firefox_and_deleted_database_do_not_invent_deleted_visits(self):
        path = self.root / "places.sqlite"
        firefox(path)
        self.add(path, "/home/me/.mozilla/firefox/profile/places.sqlite", deleted="deleted")
        self.assertEqual(extract_history(self.store), 0)
        self.assertEqual(len(self.records()), 1)
        row = self.records()[0]
        self.assertEqual(row["visited_utc"], "2024-01-02T03:04:05.123456Z")
        source = json.loads(row["source"])
        self.assertEqual(source["database_deleted"], "deleted")
        self.assertEqual(source["history_entry_deleted"], "not established")

    def test_wal_only_committed_visits_and_source_unchanged(self):
        path = self.root / "History"
        db = chromium(path, wal=True)
        try:
            original = "/home/me/.config/BraveSoftware/Brave-Browser/Default/History"
            exported = self.add(path, original)
            wal = self.add(Path(str(path) + "-wal"), original + "-wal", "Ewal")
            before = (exported.read_bytes(), wal.read_bytes())
            self.assertEqual(extract_history(self.store), 0)
            self.assertEqual(len(self.records()), 2)
            self.assertTrue(all(json.loads(r["source"])["wal_file_id"] == "Ewal" for r in self.records()))
            self.assertEqual(before, (exported.read_bytes(), wal.read_bytes()))
            self.assertFalse(list((self.store.root / "private").glob("browser-*")))
        finally:
            db.close()

    def test_row_limit_reparse_and_missing_wal_coverage(self):
        path = self.root / "History"
        chromium(path).close()
        self.add(path, "/profile/History")
        self.assertEqual(extract_history(self.store, max_rows=1), 2)
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(extract_history(self.store, max_rows=10), 0)
        self.assertEqual(len(self.records()), 2)
        wal = self.root / "wal"
        wal.write_bytes(b"unavailable test WAL")
        self.add(wal, "/profile/History-wal", "Ewal", status="partial")
        self.assertEqual(extract_history(self.store), 2)
        detail = json.loads(self.store.db.execute("SELECT detail FROM browser_sources WHERE file_id='Etest'").fetchone()[0])
        self.assertTrue(any("WAL" in note for note in detail["notes"]))

    def test_old_chromium_summary_and_bookmark_only_firefox(self):
        path = self.root / "Archived History"
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,visit_count INTEGER,last_visit_time INTEGER)")
            db.execute("INSERT INTO urls VALUES(1,'https://example.net/',12,?)", (CHROME_TIME,))
        self.add(path, "/profile/Archived History")
        self.assertEqual(extract_history(self.store), 0)
        self.assertEqual(self.records()[0]["kind"], "url-summary")
        self.assertEqual(self.records()[0]["visit_count"], 12)
        path = self.root / "places.sqlite"
        firefox(path)
        with sqlite3.connect(path) as db:
            db.execute("DELETE FROM moz_historyvisits")
        self.add(path, "/profile/places.sqlite", "Eff")
        self.assertEqual(extract_history(self.store), 0)
        self.assertEqual(len(self.records()), 1)

    def test_corrupt_and_unrelated_sqlite_do_not_abort_case(self):
        path = self.root / "History"
        path.write_bytes(b"SQLite format 3\0broken")
        self.add(path, "/profile/History")
        other = self.root / "other.sqlite"
        with sqlite3.connect(other) as db:
            db.execute("CREATE TABLE unrelated(x)")
        self.add(other, "/other.sqlite", "Eother")
        self.assertEqual(extract_history(self.store), 2)
        states = dict(self.store.db.execute("SELECT file_id,status FROM browser_sources"))
        self.assertEqual(states["Etest"], "partial")
        self.assertEqual(states["Eother"], "not-browser")

    def test_history_reports_mask_url_secrets_escape_html_and_csv_formulas(self):
        path = self.root / "History"
        db = chromium(path)
        secret_url = "https://user:password@example.org/" + WIF + "?token=private-query#private-fragment"
        db.execute("UPDATE urls SET url=?,title=?", (secret_url, '=HYPERLINK("<script>bad</script>")'))
        db.commit()
        db.close()
        self.add(path, "/profile/History")
        extract_history(self.store)
        write_report(self.store)
        for name in ("browser-history.html", "browser-history.json", "browser-history.csv"):
            text = (self.store.root / name).read_text()
            for secret in (WIF, "user:password", "private-query", "private-fragment"):
                self.assertNotIn(secret, text)
        html = (self.store.root / "browser-history.html").read_text()
        self.assertNotIn("<script>bad</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("'=HYPERLINK", (self.store.root / "browser-history.csv").read_text())
        self.assertEqual(self.records()[0]["url"], secret_url)

    def test_domain_boundaries_and_invalid_timestamps(self):
        self.assertTrue(crypto_domain(domain("https://accounts.coinbase.com/")))
        self.assertFalse(crypto_domain(domain("https://coinbase.com.evil.example/")))
        self.assertFalse(crypto_domain(domain("https://notcoinbase.com/")))
        for value in (None, 0, -1, 2**63 - 1, "123"):
            self.assertIsNone(timestamp(value, "chromium"))
        for name in ("/profile/History", "/profile/History-wal", r"C:\profile\places.sqlite"):
            self.assertTrue(history_name(name))
            self.assertEqual(classify(name)[0], "browser")

    def test_existing_case_history_command(self):
        path = self.root / "History"
        chromium(path).close()
        self.add(path, "/profile/History")
        for stage in ("raw", "filesystem", "carving", "enrichment"):
            self.store.stage(stage, "complete")
        self.store.put("status", "complete")
        self.assertEqual(main(["history", str(self.store.root), "--max-rows", "1"]), 2)
        limited = json.loads((self.store.root / "findings.json").read_text())
        self.assertEqual(limited["status"], "complete-with-gaps")
        self.assertEqual(main(["history", str(self.store.root)]), 0)
        complete = json.loads((self.store.root / "findings.json").read_text())
        self.assertEqual(complete["status"], "complete")
        self.assertTrue((self.store.root / "browser-history.html").exists())

    def test_sqlite_views_are_not_treated_as_browser_tables(self):
        path = self.root / "History"
        with sqlite3.connect(path) as db:
            db.execute("CREATE VIEW urls AS SELECT 1 id,load_extension('/bad') url")
        self.add(path, "/profile/History")
        self.assertEqual(extract_history(self.store), 2)
        self.assertEqual(len(self.records()), 0)
