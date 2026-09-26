"""Read-only extraction of Chromium, Firefox and Internet Explorer evidence.

Only exported artifacts are read. Matching live WALs are read alongside a disposable
copy; original artifacts never acquire SQLite journal or shared-memory sidecars.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
from urllib.parse import urlsplit

from .detect import Hit
from .ie import extract_ie, ie_format, ie_name, reader
from .util import log

PARSER_VERSION = 2
SQLITE_MAGIC = b"SQLite format 3\0"
HISTORY_NAMES = {"history", "archived history", "places.sqlite"}
# Triage vocabulary, not a list of trusted/current services. Historical domains
# remain useful evidence. Matches require an exact hostname or subdomain boundary.
CRYPTO_DOMAINS = {"bitcoin.org", "bitcointalk.org", "electrum.org", "ethereum.org", "metamask.io",
                  "blockchain.info", "blockchain.com", "coinbase.com", "binance.com", "kraken.com",
                  "etherscan.io", "blockstream.info", "myetherwallet.com", "exodus.com", "trezor.io",
                  "ledger.com", "getmonero.org", "mtgox.com", "bittrex.com", "poloniex.com"}


def history_name(path, sidecars=True):
    if ie_name(path, sidecars):
        return True
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if sidecars:
        for suffix in ("-wal", "-shm", "-journal"):
            if name.endswith(suffix):
                name = name[:-len(suffix)]
                break
    return name in HISTORY_NAMES


def timestamp(value, family):
    if not isinstance(value, int) or value <= 0:
        return None
    epoch = datetime(1601 if family == "chromium" else 1970, 1, 1, tzinfo=timezone.utc)
    try:
        return (epoch + timedelta(microseconds=value)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def domain(url):
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in ("http", "https", "ftp"):
            return ""
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def crypto_domain(host):
    return any(host == item or host.endswith("." + item) for item in CRYPTO_DOMAINS)


def browser_label(family, path):
    normalized = path.replace("\\", "/").lower()
    if family == "firefox":
        return "Firefox-family"
    for fragment, label in (("brave", "Brave"), ("microsoft/edge", "Edge"), ("microsoft-edge", "Edge"),
                            ("vivaldi", "Vivaldi"), ("opera", "Opera"), ("google/chrome", "Chrome"),
                            ("google-chrome", "Chrome"), ("chromium", "Chromium")):
        if fragment in normalized:
            return label
    return "Chromium-family"


def schema(db):
    names = ("urls", "visits", "visit_source", "moz_places", "moz_historyvisits")
    tables = {}
    for name, sql in db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name IN (?,?,?,?,?)", names):
        if not sql or "VIRTUAL TABLE" in sql.upper():
            continue
        # name has been selected from a fixed, trusted whitelist.
        tables[name] = {row[1] for row in db.execute(f'PRAGMA table_info("{name}")')}
    return tables


def query_for(tables):
    if {"id", "url"} <= tables.get("urls", set()):
        family, table, visits = "chromium", "urls", "visits"
        join_key, time_col, last_col, transition = "url", "visit_time", "last_visit_time", "transition"
    elif {"id", "url"} <= tables.get("moz_places", set()):
        family, table, visits = "firefox", "moz_places", "moz_historyvisits"
        join_key, time_col, last_col, transition = "place_id", "visit_date", "last_visit_date", "visit_type"
    else:
        return None
    columns = tables[table]
    title = "u.title" if "title" in columns else "NULL"
    count = "u.visit_count" if "visit_count" in columns else "NULL"
    if {"id", join_key, time_col} <= tables.get(visits, set()):
        vcols = tables[visits]
        trans = f"v.{transition}" if transition in vcols else "NULL"
        origin = "v.originator_cache_guid" if "originator_cache_guid" in vcols else "NULL"
        previous = "v.from_visit" if "from_visit" in vcols else "NULL"
        source_code, extra_join = "NULL", ""
        if family == "chromium" and {"id", "source"} <= tables.get("visit_source", set()):
            source_code = "s.source"
            extra_join = " LEFT JOIN visit_source s ON s.id=v.id"
        query = (f"SELECT v.id,u.id,u.url,{title},v.{time_col},{count},{trans},{origin},{previous},{source_code} "
                 f"FROM {visits} v JOIN {table} u ON u.id=v.{join_key}{extra_join} ORDER BY v.id LIMIT ?")
        return family, "visit", visits, query
    # URL metadata is not an individual visit. Firefox places may be bookmarks
    # only: require a positive last-visit timestamp and count for summaries.
    if last_col not in columns or "visit_count" not in columns:
        return family, "unsupported", table, None
    query = (f"SELECT u.id,u.id,u.url,{title},u.{last_col},{count},NULL,NULL,NULL,NULL FROM {table} u "
             f"WHERE u.{last_col}>0 AND u.visit_count>0 ORDER BY u.id LIMIT ?")
    return family, "url-summary", table, query


def safe_reader(path):
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
    db.text_factory = lambda value: value.decode("utf-8", "replace")
    db.execute("PRAGMA trusted_schema=OFF")
    db.execute("PRAGMA query_only=ON")
    db.execute("PRAGMA temp_store=MEMORY")
    db.execute("PRAGMA cache_size=-8192")
    db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024 * 1024)
    deadline = time.monotonic() + 30
    instructions = 0
    def progress():
        nonlocal instructions
        instructions += 10000
        return int(instructions > 20_000_000 or time.monotonic() > deadline)
    db.set_progress_handler(progress, 10000)
    # Queries below need only schema introspection and SELECTs, never extensions,
    # attached databases, writes, or stored views/triggers.
    def authorize(action, arg1, arg2, database, trigger):
        allowed = action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ)
        if action == sqlite3.SQLITE_PRAGMA and arg1 == "table_info":
            allowed = True
        return sqlite3.SQLITE_OK if allowed else sqlite3.SQLITE_DENY
    db.set_authorizer(authorize)
    return db


def sidecar_for(store, row):
    notes = []
    if row["volume"] is None or row["deleted"] != "allocated":
        return None, ["No WAL association attempted for carved/deleted database; base snapshot only."]
    matches = list(store.db.execute("SELECT * FROM files WHERE volume=? AND path=? AND deleted='allocated'",
                                   (row["volume"], row["path"] + "-wal")))
    journal = store.db.execute("SELECT id FROM files WHERE volume=? AND path=? AND size>0",
                               (row["volume"], row["path"] + "-journal")).fetchone()
    if journal:
        notes.append("Rollback journal present; rollback recovery is not implemented.")
    if not matches:
        return None, notes
    if len(matches) != 1 or matches[0]["status"] != "exported" or not matches[0]["artifact"]:
        return None, notes + ["Matching WAL was ambiguous or not completely exported; base snapshot only."]
    if matches[0]["size"] == 0:
        return None, notes
    return matches[0], notes


def extract_one(store, row, wal, notes, limit):
    count = 0
    family = None
    status = "complete"
    # Old rows are replaced transactionally on reparse, including limits/WAL changes.
    store.db.execute("DELETE FROM browser_history WHERE file_id=?", (row["id"],))
    source = {"method": "browser-sqlite", "file_id": row["id"], "volume": row["volume"],
              "path": row["path"], "artifact": row["artifact"], "database_deleted": row["deleted"],
              "history_entry_deleted": "not established", "wal_file_id": wal["id"] if wal else None}
    try:
        with tempfile.TemporaryDirectory(prefix="browser-", dir=store.root / "private") as temp:
            path = Path(temp) / "history.sqlite"
            shutil.copyfile(store.root / row["artifact"], path)
            if wal:
                shutil.copyfile(store.root / wal["artifact"], path.with_name("history.sqlite-wal"))
            db = safe_reader(path)
            try:
                selected = query_for(schema(db))
                if not selected:
                    return "unsupported" if history_name(row["path"], False) else "not-browser", {
                        "notes": notes + ["No supported browser-history schema found"], "records": 0}
                family, kind, table, query = selected
                if query is None:
                    return "unsupported", {"family": family, "records": 0, "notes": notes + ["History schema lacks required visit/time columns"]}
                if kind == "url-summary":
                    notes.append("Individual visits unavailable; entries describe URL-level last-visit metadata.")
                for record in db.execute(query, (limit + 1,)):
                    if count >= limit:
                        status = "partial"
                        notes.append(f"Row limit {limit} reached; increase --max-browser-rows or history --max-rows.")
                        break
                    record_id, url_id, url, title, raw_time, visits, transition, remote, previous, source_code = record
                    if not isinstance(url, str) or not isinstance(record_id, int):
                        status = "partial"
                        continue
                    ident = "H" + hashlib.sha256(f"{row['id']}:{table}:{record_id}".encode()).hexdigest()[:20]
                    host = domain(url)
                    origin = "Remote/synced origin recorded" if remote else "Origin not established; may include synced/imported visits"
                    record_source = dict(source, table=table, record_id=record_id, url_id=url_id,
                                         from_visit=previous, visit_source_code=source_code,
                                         originator_cache_guid=remote, wal_snapshot=bool(wal))
                    store.db.execute("""INSERT OR REPLACE INTO browser_history
                        (id,file_id,browser,family,profile,kind,record_id,url,title,domain,visited_utc,
                         visited_raw,epoch,visit_count,transition,origin,source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (ident, row["id"], browser_label(family, row["path"]), family,
                         row["path"].replace("\\", "/").rsplit("/", 1)[0], kind, str(record_id), url,
                         title if isinstance(title, str) else "", host, timestamp(raw_time, family),
                         str(raw_time) if raw_time is not None else None,
                         "microseconds since 1601-01-01 UTC" if family == "chromium" else "microseconds since 1970-01-01 UTC",
                         visits if isinstance(visits, int) else None, str(transition) if transition is not None else None,
                         origin, json.dumps(record_source)))
                    count += 1
            finally:
                db.close()
    except (sqlite3.Error, OSError, ValueError) as exc:
        status = "partial"
        notes.append(f"History parsing incomplete: {type(exc).__name__}; original artifact retained.")
    if row["status"] != "exported" or any("not implemented" in note or "Matching WAL" in note for note in notes):
        status = "partial"
    if count:
        store.finding(Hit("browser_history_database", "Recovered browser-history records", row["id"].encode(), 0, 0,
                          confidence="high", validation="Structured database records; visits may be synced/imported and are not proof of a person's activity",
                          category="interesting"), dict(source, family=family))
    return status, {"family": family, "records": count, "notes": notes,
                    "wal_file_id": wal["id"] if wal else None,
                    "scope": "Live SQL rows only; cleared/deleted SQLite cells and old WAL frames are not carved."}


def extract_history(store, max_rows=100000):
    if max_rows <= 0:
        raise ValueError("Browser row limit must be positive")
    store.stage("browser_history", "running", "Reading recovered Chromium/Firefox/Internet Explorer history")
    for row in store.db.execute("SELECT * FROM files ORDER BY priority,id").fetchall():
        if json.loads(row["metadata"]).get("mode", "").startswith("d"):
            continue
        named = history_name(row["path"], False)
        if not row["artifact"]:
            if named:
                detail = {"records": 0, "notes": [f"History file not exported ({row['status']}); resume recovery to retry."]}
                store.db.execute("INSERT OR REPLACE INTO browser_sources VALUES (?,?,?,?,?)",
                                 (row["id"], "", "unavailable", json.dumps(detail), row["path"]))
            continue
        with (store.root / row["artifact"]).open("rb") as stream:
            header = stream.read(64)
            is_sqlite = header[:16] == SQLITE_MAGIC
        family = ie_format(row["path"], header)
        if family:
            revision = hashlib.sha256(json.dumps([PARSER_VERSION, row["sha256"], row["status"],
                                                 family, reader(family), max_rows], sort_keys=True).encode()).hexdigest()
            old = store.db.execute("SELECT revision,status FROM browser_sources WHERE file_id=?", (row["id"],)).fetchone()
            if old and old["revision"] == revision and old["status"] in ("complete", "not-browser"):
                continue
            status, detail = extract_ie(store, row, family, header, max_rows)
            store.db.execute("INSERT OR REPLACE INTO browser_sources VALUES (?,?,?,?,?)",
                             (row["id"], revision, status, json.dumps(detail), row["path"]))
            store.db.commit()
            if status != "not-browser":
                log(f"Browser history: {row['id']}, {detail['records']} records, {status}")
            continue
        if not (named or is_sqlite):
            continue
        wal, notes = sidecar_for(store, row)
        revision = hashlib.sha256(json.dumps([PARSER_VERSION, row["sha256"], row["status"],
                                            wal["sha256"] if wal else None, notes, max_rows]).encode()).hexdigest()
        old = store.db.execute("SELECT revision,status FROM browser_sources WHERE file_id=?", (row["id"],)).fetchone()
        if old and old["revision"] == revision and old["status"] in ("complete", "not-browser"):
            continue
        status, detail = extract_one(store, row, wal, notes, max_rows)
        store.db.execute("INSERT OR REPLACE INTO browser_sources VALUES (?,?,?,?,?)",
                         (row["id"], revision, status, json.dumps(detail), row["path"]))
        store.db.commit()
        if status != "not-browser":
            log(f"Browser history: {row['id']}, {detail['records']} records, {status}")
    # Rebuild this detector's occurrences to avoid stale derived leads on reparse.
    store.db.execute("DELETE FROM occurrences WHERE finding_id IN (SELECT id FROM findings WHERE kind='crypto_browser_domain')")
    store.db.execute("DELETE FROM findings WHERE kind='crypto_browser_domain'")
    for row in store.db.execute("SELECT id,domain,source,visited_utc FROM browser_history"):
        if crypto_domain(row["domain"]):
            source = dict(json.loads(row["source"]), history_id=row["id"], visited_utc=row["visited_utc"], domain=row["domain"])
            store.finding(Hit("crypto_browser_domain", "Crypto-related domain in browser history", row["domain"].encode(), 0, 0,
                              validation="Domain triage match only; no proof of account ownership, wallet use or funds"), source)
    count = store.db.execute("SELECT count(*) FROM browser_history").fetchone()[0]
    issues = store.db.execute("SELECT count(*) FROM browser_sources WHERE status NOT IN ('complete','not-browser')").fetchone()[0]
    filesystem = store.stage_row("filesystem").get("status")
    incomplete_recovery = filesystem is not None and filesystem != "complete"
    recovery_note = (f" Filesystem recovery is {filesystem}; history coverage is incomplete."
                     if incomplete_recovery else "")
    store.stage("browser_history", "partial" if issues or incomplete_recovery else "complete",
                f"{count} structured records; {issues} incomplete/unsupported sources.{recovery_note} See per-source recovery scope; missing/private/cleared history is not inferred.")
    return 2 if issues or incomplete_recovery else 0
