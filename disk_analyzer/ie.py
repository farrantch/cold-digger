"""Internet Explorer history adapters with bounded, isolated native readers."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

from .detect import Hit
from .process import run_file

WORKER = Path(__file__).with_name("ie_worker.py")
IE_NAMES = {"index.dat", "webcachev01.dat", "webcachev24.dat"}
ESE_MAGIC = b"\xef\xcd\xab\x89"


def ie_name(path, sidecars=True):
    normalized = path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    if name in IE_NAMES:
        return True
    return bool(sidecars and "/webcache/" in normalized and re.fullmatch(r"v\d{2}(?:[0-9a-f]{5,8}|tmp|res\d{5})?\.(?:log|chk|jrs)", name))


def ie_format(path, header):
    if ie_name(path) and not ie_name(path, False):
        return None  # Transaction logs/checkpoints are retained, not databases.
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if header.startswith(b"Client UrlCache MMF Ver "):
        return "ie-index"
    if header[4:8] == ESE_MAGIC and header[12:16] == b"\0" * 4:
        return "ie-webcache"
    if name == "index.dat":
        return "ie-index"
    if name in ("webcachev01.dat", "webcachev24.dat"):
        return "ie-webcache"
    return None


@lru_cache(maxsize=2)
def reader(family):
    for executable in dict.fromkeys((sys.executable, "/usr/bin/python3")):
        try:
            result = subprocess.run([executable, str(WORKER), family, "--probe"],
                                    capture_output=True, timeout=10, check=False)
            if result.returncode == 0:
                return {**json.loads(result.stdout), "python": executable}
        except (OSError, subprocess.TimeoutExpired, ValueError):
            continue
    return {"available": False, "module": "pymsiecf" if family == "ie-index" else "pyesedb"}


def filetime(value):
    if not isinstance(value, int) or value <= 1 or value >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        result = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)
        # Preserve the seventh decimal digit instead of silently rounding FILETIME.
        return result.strftime("%Y-%m-%dT%H:%M:%S") + f".{value % 10000000:07d}Z"
    except (OverflowError, ValueError):
        return None


def unwrap_location(location):
    # index.dat/WebCache history can prefix a URL with "Visited: user@" or
    # "YYYYMMDDYYYYMMDD:user@". Retain the original in private worker output.
    match = re.match(r"^(?:Visited:\s*|\d{16}:)[^@]*@((?:https?|ftp|file)://.*)$", location, re.I)
    return match.group(1) if match else location


def normalized_record(item, family):
    raw = item.get("accessed_time")
    kind = "url-summary"
    semantics = "Last access recorded in a WebCache history container; not an individual visit"
    if family == "ie-index":
        category = item.get("item_type")
        if category in ("history", "history-daily"):
            raw = item.get("primary_time")
            semantics = "Last visit in index.dat history metadata; not an individual visit"
        elif category == "history-weekly":
            raw = item.get("secondary_time")
            return unwrap_location(item["location"]), None, raw, "url-summary-local-time", "Local FILETIME; source timezone unknown; no UTC conversion"
        else:
            # Cache/cookie/redirect records are useful leads but must never be
            # assigned a visit time from a server modification/cache timestamp.
            raw = None
            kind = "cache-reference" if category == "cache" else "browser-reference"
            semantics = "Cache/other URL evidence; no browsing visit established"
    return unwrap_location(item["location"]), filetime(raw), raw, kind, semantics


def extract_ie(store, row, family, header, max_rows):
    info = reader(family)
    detail = {"family": family, "records": 0, "reader": info, "notes": [],
              "scope": "index.dat URL and recovered items" if family == "ie-index" else
                       "WebCache History/MSHist container rows; no deleted ESE pages or transaction-log replay"}
    store.db.execute("DELETE FROM browser_history WHERE file_id=?", (row["id"],))
    if not info["available"]:
        package = "python3-libmsiecf" if family == "ie-index" else "python3-libesedb"
        detail["notes"].append(f"Reader unavailable; install {package} or use the supplied Ubuntu container.")
        return "unavailable", detail
    if family == "ie-webcache":
        state = int.from_bytes(header[52:56], "little") if len(header) >= 56 else None
        detail["ese_database_state"] = state
        detail["notes"].append("Base ESE snapshot only; transaction logs are retained when found but not replayed.")
        if state != 3:
            detail["notes"].append("ESE header is not clean-shutdown state 3; recent records may require log replay.")
    output = store.root / "private" / (row["id"] + "-ie.jsonl")
    error = store.root / "logs" / (row["id"] + "-ie.stderr")
    code, reason = run_file([info["python"], str(WORKER), family, str(store.root / row["artifact"]), str(max_rows)],
                            output, error, timeout=300, max_bytes=128 * 1024**2)
    status = "partial" if code or reason or row["status"] != "exported" else "complete"
    if family == "ie-webcache" and detail["ese_database_state"] != 3:
        status = "partial"
    summary = None
    source = {"method": family, "file_id": row["id"], "volume": row["volume"], "path": row["path"],
              "artifact": row["artifact"], "database_deleted": row["deleted"],
              "history_entry_deleted": "not established", "native_export": str(output.relative_to(store.root))}
    with output.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                item = json.loads(line)
            except ValueError:
                status = "partial"
                break
            if item.get("event") == "summary":
                summary = item
                continue
            if item.get("event") != "record":
                status = "partial"
                continue
            if detail["records"] >= max_rows or not isinstance(item.get("location"), str):
                status = "partial"
                continue
            url, visited, raw, kind, semantics = normalized_record(item, family)
            try:
                parts = urlsplit(url)
                host = (parts.hostname or "").lower().rstrip(".") if parts.scheme in ("http", "https", "ftp") else ""
            except ValueError:
                host = ""
            ident = "H" + hashlib.sha256(f"{row['id']}:{family}:{item['table']}:{item['record_id']}".encode()).hexdigest()[:20]
            provenance = dict(source, **{key: value for key, value in item.items() if key not in ("location", "event")},
                              time_semantics=semantics, record_state="recovered candidate" if item.get("recovered") else "reader-enumerated")
            label = "Internet Explorer" if family == "ie-index" else "Internet Explorer / Windows WebCache"
            epoch = "100-nanosecond intervals since 1601-01-01; LOCAL time, timezone unknown" if kind.endswith("local-time") else "100-nanosecond intervals since 1601-01-01 UTC"
            store.db.execute("""INSERT OR REPLACE INTO browser_history
                (id,file_id,browser,family,profile,kind,record_id,url,title,domain,visited_utc,
                 visited_raw,epoch,visit_count,transition,origin,source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ident, row["id"], label, family, row["path"].replace("\\", "/").rsplit("/", 1)[0], kind,
                 str(item["record_id"]), url, "", host, visited, str(raw) if raw is not None else None,
                 epoch, item.get("access_count"), None, semantics, json.dumps(provenance)))
            detail["records"] += 1
    if summary is None:
        status = "partial"
        detail["notes"].append("Native reader did not finish; available records retained.")
    else:
        detail["native_summary"] = summary
        if summary.get("not_browser"):
            status = "unsupported" if ie_name(row["path"], False) else "not-browser"
        if summary.get("limited"):
            detail["notes"].append(f"Row limit {max_rows} reached; increase --max-browser-rows or history --max-rows.")
        if summary.get("errors"):
            detail["notes"].append("Some native records could not be decoded.")
    if reason:
        detail["notes"].append(reason)
    if detail["records"]:
        store.finding(Hit("browser_history_database", "Recovered browser-history records", row["id"].encode(), 0, 0,
                          confidence="high", validation="Structured browser evidence; cache references and last-visit summaries are not individual visits",
                          category="interesting"), dict(source, family=family))
    return status, detail
