from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import time

from .util import atomic_write


class Store:
    def __init__(self, root: Path):
        self.root = root
        for name in ("private", "artifacts", "logs", "thumbnails"):
            (root / name).mkdir(mode=0o700, exist_ok=True)
        self.db = sqlite3.connect(root / "case.sqlite")
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS stages (
                name TEXT PRIMARY KEY, status TEXT, detail TEXT, progress INTEGER DEFAULT 0,
                updated REAL);
            CREATE TABLE IF NOT EXISTS volumes (
                id TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY, volume TEXT, inode TEXT, path TEXT, size INTEGER,
                deleted TEXT, category TEXT, priority INTEGER, metadata TEXT,
                status TEXT DEFAULT 'pending', artifact TEXT, sha256 TEXT, detail TEXT);
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, kind TEXT, category TEXT, title TEXT, confidence TEXT,
                validation TEXT, fingerprint TEXT, secret_path TEXT);
            CREATE INDEX IF NOT EXISTS files_recovery ON files(priority,size,id);
            CREATE INDEX IF NOT EXISTS files_path ON files(volume,path,id);
            CREATE TABLE IF NOT EXISTS occurrences (
                id TEXT PRIMARY KEY, finding_id TEXT REFERENCES findings(id), source TEXT);
            CREATE INDEX IF NOT EXISTS occurrence_finding ON occurrences(finding_id);
            CREATE TABLE IF NOT EXISTS analyses (id INTEGER PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS finding_material (
                finding_id TEXT PRIMARY KEY REFERENCES findings(id), path TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS crypto_assessments (
                finding_id TEXT PRIMARY KEY REFERENCES findings(id), revision TEXT, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS balances (
                chain TEXT, address TEXT, provider TEXT, checked_at TEXT, status TEXT, data TEXT,
                PRIMARY KEY(chain,address,provider));
            CREATE TABLE IF NOT EXISTS browser_sources (
                file_id TEXT PRIMARY KEY REFERENCES files(id), revision TEXT,
                status TEXT, detail TEXT, path TEXT);
            CREATE TABLE IF NOT EXISTS browser_history (
                id TEXT PRIMARY KEY, file_id TEXT REFERENCES files(id), browser TEXT,
                family TEXT, profile TEXT, kind TEXT, record_id TEXT, url TEXT, title TEXT,
                domain TEXT, visited_utc TEXT, visited_raw TEXT, epoch TEXT,
                visit_count INTEGER, transition TEXT, origin TEXT, source TEXT);
            CREATE INDEX IF NOT EXISTS history_file ON browser_history(file_id);
            CREATE INDEX IF NOT EXISTS history_time ON browser_history(visited_utc);
        """)

    def close(self):
        self.db.commit()
        self.db.close()

    def get(self, key, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, json.dumps(value)))
        self.db.commit()

    def stage(self, name, status, detail="", progress=0):
        self.db.execute("INSERT OR REPLACE INTO stages VALUES (?,?,?,?,?)",
                        (name, status, detail, progress, time.time()))
        self.db.commit()

    def stage_row(self, name):
        row = self.db.execute("SELECT * FROM stages WHERE name=?", (name,)).fetchone()
        return dict(row) if row else {}

    def done(self, name):
        return self.stage_row(name).get("status") == "complete"

    def volume(self, value):
        self.db.execute("INSERT OR REPLACE INTO volumes VALUES (?,?)",
                        (value["id"], json.dumps(value)))
        self.db.commit()

    def volumes(self):
        return [json.loads(r[0]) for r in self.db.execute("SELECT data FROM volumes ORDER BY id")]

    def finding(self, hit, source):
        from .detect import MATERIAL_KINDS
        fingerprint = hashlib.sha256(hit.value).hexdigest()
        ident = "F" + hashlib.sha256((hit.kind + fingerprint).encode()).hexdigest()[:20]
        private_path = None
        if hit.secret:
            private_path = f"private/{ident}.bin"
            if not (self.root / private_path).exists():
                atomic_write(self.root / private_path, hit.value)
        self.db.execute("INSERT OR IGNORE INTO findings VALUES (?,?,?,?,?,?,?,?)",
                        (ident, hit.kind, hit.category, hit.title, hit.confidence,
                         hit.validation, fingerprint, private_path))
        if hit.secret or hit.kind in MATERIAL_KINDS:
            material = private_path or f"private/{ident}.value"
            if not (self.root / material).exists():
                atomic_write(self.root / material, hit.value)
            self.db.execute("INSERT OR IGNORE INTO finding_material VALUES (?,?)", (ident, material))
        serialized = json.dumps(source, sort_keys=True)
        occurrence = hashlib.sha256((ident + serialized).encode()).hexdigest()
        self.db.execute("INSERT OR IGNORE INTO occurrences VALUES (?,?,?)",
                        (occurrence, ident, serialized))
        return ident

    def findings(self):
        for row in self.db.execute("SELECT * FROM findings ORDER BY CASE category WHEN 'crypto' THEN 0 ELSE 1 END, id"):
            item = dict(row)
            item["sources"] = [json.loads(r[0]) for r in self.db.execute(
                "SELECT source FROM occurrences WHERE finding_id=? ORDER BY id", (item["id"],))]
            yield item

    def file(self, value):
        self.db.execute("""INSERT OR IGNORE INTO files
            (id,volume,inode,path,size,deleted,category,priority,metadata)
            VALUES (:id,:volume,:inode,:path,:size,:deleted,:category,:priority,:metadata)""", value)

    def file_status(self, ident, status, detail="", artifact=None, sha256=None):
        self.db.execute("UPDATE files SET status=?,detail=?,artifact=?,sha256=? WHERE id=?",
                        (status, detail, artifact, sha256, ident))
        self.db.commit()
