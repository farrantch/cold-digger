import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from disk_analyzer.browser import extract_history, history_name
from disk_analyzer.content import classify
from disk_analyzer.ie import ESE_MAGIC, filetime, ie_format, normalized_record, reader, unwrap_location
from disk_analyzer.ie_worker import Budget, read_webcache
from disk_analyzer.report import write_report
from disk_analyzer.store import Store

FILETIME = 133486382451234567
READER = {"available": True, "module": "pymsiecf", "version": "test", "python": "/usr/bin/python3"}


class CaseTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "case").mkdir()
        self.store = Store(self.root / "case")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def add(self, data, path, ident="Eie"):
        category, priority = classify(path)
        artifact = "artifacts/" + ident + ".bin"
        (self.store.root / artifact).write_bytes(data)
        self.store.file({"id": ident, "volume": "p1", "inode": ident, "path": path, "size": len(data),
                         "deleted": "allocated", "category": category, "priority": priority, "metadata": "{}"})
        self.store.file_status(ident, "exported", artifact=artifact, sha256=hashlib.sha256(data).hexdigest())

    def records(self):
        return list(self.store.db.execute("SELECT * FROM browser_history ORDER BY id"))


class IETests(CaseTest):
    def test_filetime_precision_sentinels_and_wrapped_locations(self):
        self.assertEqual(filetime(FILETIME), "2024-01-02T03:04:05.1234567Z")
        for value in (None, 0, 1, -1, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, "123"):
            self.assertIsNone(filetime(value))
        for text in ("Visited: alice@https://electrum.org/", "2024010120240108:alice@https://electrum.org/"):
            self.assertEqual(unwrap_location(text), "https://electrum.org/")
        self.assertEqual(unwrap_location("https://example.org/a@b"), "https://example.org/a@b")

    def test_weekly_local_times_and_cache_references_are_not_utc_visits(self):
        record = {"location": "Visited: alice@https://example.org/", "item_type": "history-weekly",
                  "primary_time": FILETIME - 10000000, "secondary_time": FILETIME}
        normalized = normalized_record(record, "ie-index")
        self.assertIsNone(normalized[1])
        self.assertEqual(normalized[2], FILETIME)
        self.assertEqual(normalized[3], "url-summary-local-time")
        record["item_type"] = "cache"
        normalized = normalized_record(record, "ie-index")
        self.assertIsNone(normalized[1])
        self.assertIsNone(normalized[2])
        self.assertEqual(normalized[3], "cache-reference")

    def test_names_signatures_and_sidecars(self):
        for name in ("/History.IE5/index.dat", r"C:\Users\test\WebCache\WebCacheV01.dat",
                     "/webcache/WebCacheV24.dat", "/WebCache/V0100001.log", "/WebCache/V01.chk",
                     "/WebCache/V01res00001.jrs"):
            self.assertTrue(history_name(name))
            self.assertEqual(classify(name)[0], "browser")
        self.assertEqual(ie_format("/carved/f1.dat", b"Client UrlCache MMF Ver 5.2\0"), "ie-index")
        header = b"\0" * 4 + ESE_MAGIC + b"\0" * 56
        self.assertEqual(ie_format("/carved/f2.bin", header), "ie-webcache")
        self.assertIsNone(ie_format("/WebCache/V01.log", header))
        self.assertFalse(history_name("/unrelated/V01.log"))

    def test_missing_reader_is_reported_and_can_be_retried(self):
        self.add(b"Client UrlCache MMF Ver 5.2\0", "/History.IE5/index.dat")
        unavailable = {"available": False, "module": "pymsiecf"}
        with patch("disk_analyzer.browser.reader", return_value=unavailable), patch("disk_analyzer.ie.reader", return_value=unavailable):
            self.assertEqual(extract_history(self.store), 2)
        self.assertEqual(self.store.db.execute("SELECT status FROM browser_sources").fetchone()[0], "unavailable")
        self.assertEqual(len(self.records()), 0)

    def feed(self, records, summary=None, code=0):
        def run(argv, output, error, **kwargs):
            output.write_text("".join(json.dumps(item) + "\n" for item in records + ([summary] if summary else [])))
            error.write_bytes(b"")
            return code, ""
        return run

    def test_index_provenance_masking_crypto_lead_and_resume(self):
        self.add(b"Client UrlCache MMF Ver 5.2\0", "/History.IE5/index.dat")
        record = {"event": "record", "table": "recovered", "record_id": 1, "offset": 20480,
                  "recovered": True, "location": "Visited: alice@https://electrum.org/?private_token=hidden",
                  "item_type": "history", "primary_time": FILETIME, "secondary_time": FILETIME,
                  "access_count": 3}
        summary = {"event": "summary", "records": 1, "errors": 0, "limited": False}
        with patch("disk_analyzer.browser.reader", return_value=READER), patch("disk_analyzer.ie.reader", return_value=READER), \
             patch("disk_analyzer.ie.run_file", side_effect=self.feed([record], summary)) as run:
            self.assertEqual(extract_history(self.store), 0)
            self.assertEqual(extract_history(self.store), 0)
            self.assertEqual(run.call_count, 1)
        row = self.records()[0]
        self.assertEqual(row["domain"], "electrum.org")
        self.assertEqual(row["kind"], "url-summary")
        self.assertEqual(row["visited_utc"], "2024-01-02T03:04:05.1234567Z")
        source = json.loads(row["source"])
        self.assertEqual(source["record_state"], "recovered candidate")
        self.assertEqual(source["history_entry_deleted"], "not established")
        self.assertEqual(source["offset"], 20480)
        self.assertTrue(any(f["kind"] == "crypto_browser_domain" for f in self.store.findings()))
        write_report(self.store)
        self.assertNotIn("private_token", (self.store.root / "browser-history.json").read_text())

    def test_dirty_ese_and_interrupted_worker_remain_partial(self):
        header = bytearray(64)
        header[4:8] = ESE_MAGIC
        header[52:56] = (2).to_bytes(4, "little")
        self.add(bytes(header), "/WebCache/WebCacheV01.dat")
        summary = {"event": "summary", "records": 0, "errors": 0, "limited": False}
        with patch("disk_analyzer.browser.reader", return_value=READER), patch("disk_analyzer.ie.reader", return_value=READER), \
             patch("disk_analyzer.ie.run_file", side_effect=self.feed([], summary)):
            self.assertEqual(extract_history(self.store), 2)
        detail = json.loads(self.store.db.execute("SELECT detail FROM browser_sources").fetchone()[0])
        self.assertTrue(any("log replay" in note for note in detail["notes"]))
        with patch("disk_analyzer.browser.reader", return_value=READER), patch("disk_analyzer.ie.reader", return_value=READER), \
             patch("disk_analyzer.ie.run_file", side_effect=self.feed([], code=-11)):
            self.assertEqual(extract_history(self.store), 2)
        detail = json.loads(self.store.db.execute("SELECT detail FROM browser_sources").fetchone()[0])
        self.assertTrue(any("did not finish" in note for note in detail["notes"]))

    def test_webcache_selects_container_names_not_numbers_and_honors_limit(self):
        class Record:
            def __init__(self, value):
                self.value = value
        class Table:
            def __init__(self, rows):
                self.rows = [Record(row) for row in rows]
                self.number_of_records = len(rows)
            def get_record(self, index):
                return self.rows[index]
        tables = {"Containers": Table([{"ContainerId": 2, "Name": "Content"}, {"ContainerId": 37, "Name": "History"}]),
                  "Container_37": Table([{"EntryId": 9, "Url": "https://example.org/", "AccessedTime": FILETIME},
                                         {"EntryId": 10, "Url": "https://example.net/", "AccessedTime": FILETIME}])}
        database = SimpleNamespace(open=lambda *args: None, close=lambda: None, get_table_by_name=tables.get)
        module = SimpleNamespace(file=lambda: database)
        budget = Budget(1)
        with patch("disk_analyzer.ie_worker.values", side_effect=lambda record, wanted: record.value), \
             patch("disk_analyzer.ie_worker.emit") as emit:
            summary = read_webcache(module, "unused", budget)
        record = emit.call_args.args[0]
        self.assertEqual(record["table"], "Container_37")
        self.assertEqual(summary["skipped_non_history_containers"], 1)
        self.assertTrue(budget.limited)
        self.assertEqual(budget.records, 1)


@unittest.skipUnless(os.environ.get("DISK_ANALYZER_IE_FIXTURES"), "Optional public IE fixtures: see docs/ie-testing.md")
class IENativeTests(CaseTest):
    def fixture(self, name, sha256):
        path = Path(os.environ["DISK_ANALYZER_IE_FIXTURES"]) / name
        data = path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), sha256)
        return data

    def test_real_index_including_recovered_records_and_unchanged_artifacts(self):
        self.assertTrue(reader("ie-index")["available"])
        data = self.fixture("index.dat", "d54847adc8be889cb687bd7c60af50153d310eb3fc32a79d20c93eecb655bfc1")
        self.add(data, "/History.IE5/index.dat")
        self.assertEqual(extract_history(self.store), 0)
        rows = self.records()
        self.assertEqual(len(rows), 17)
        first = next(r for r in rows if json.loads(r["source"])["offset"] == 20480)
        self.assertEqual(first["visited_utc"], "2015-08-25T11:05:18.5120000Z")
        self.assertEqual(first["url"], "http://www.msn.com/?ocid=iehp")
        self.assertEqual(sum(json.loads(r["source"])["recovered"] for r in rows), 2)
        self.assertEqual((self.store.root / "artifacts/Eie.bin").read_bytes(), data)
        self.assertEqual(extract_history(self.store, max_rows=1), 2)
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(extract_history(self.store), 0)
        self.assertEqual(len(self.records()), 17)

    def test_real_webcache_history_containers_and_timestamp_precision(self):
        self.assertTrue(reader("ie-webcache")["available"])
        data = self.fixture("WebCacheV01.dat", "2713e7ff413c69659442c5dcb0f23f41230fa76bf760b8aeac0ffd430d10c83e")
        self.add(data, "/WebCache/WebCacheV01.dat")
        self.assertEqual(extract_history(self.store), 0)
        rows = self.records()
        self.assertEqual(len(rows), 113)
        self.assertTrue(all(r["kind"] == "url-summary" for r in rows))
        first = next(r for r in rows if json.loads(r["source"])["table"] == "Container_2" and r["record_id"] == "0")
        self.assertEqual(first["url"], "http://code.google.com/p/libyal/wiki/Overview")
        self.assertEqual(first["visited_utc"], "2014-05-12T07:31:06.1252928Z")
        self.assertEqual((self.store.root / "artifacts/Eie.bin").read_bytes(), data)

    def test_real_cache_is_not_browsing_history(self):
        self.assertTrue(reader("ie-index")["available"])
        data = self.fixture("cache-index.dat", "d6f7d3c4cd1b05b637dca8d41fcb652cc3809a0650181e447bf609bbc81d7db9")
        self.add(data, "/Content.IE5/index.dat")
        self.assertEqual(extract_history(self.store), 0)
        rows = self.records()
        self.assertGreater(len(rows), 0)
        self.assertTrue(all(r["visited_utc"] is None and r["kind"] in ("cache-reference", "browser-reference") for r in rows))
