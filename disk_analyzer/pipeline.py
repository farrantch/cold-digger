from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import time
import xml.etree.ElementTree as ET

from . import __version__
from .browser import extract_history
from .content import analyze_artifact, artifact, classify, enrich, identify_extension, path_hits, scan_stream
from .crypto import audit
from .layout import discover, locate
from .identity import stat_identity, verify_image
from .preflight import check_dependencies
from .process import available, run_file
from .report import write_report
from .store import Store
from .util import log

DEFAULTS = {"sector_size": None, "chunk_size": 4 * 1024**2, "max_file_bytes": 4 * 1024**3,
            "max_output_bytes": 50 * 1024**3, "max_files": 0, "carve": "auto",
            "bulk": False, "ocr": False, "tool_timeout": 86400, "max_browser_rows": 100000,
            "hash_mode": "quick"}


def parse_bodyfile(line, volume):
    parts = line.rstrip("\r\n").split("|")
    if len(parts) < 11:
        raise ValueError("Malformed bodyfile row")
    inode, mode, uid, gid, size, atime, mtime, ctime, crtime = parts[-9:]
    if not re.fullmatch(r"\d+(?:-\d+){0,2}", inode):
        raise ValueError("Unsupported filesystem record identifier")
    name = "|".join(parts[1:-9])
    deleted = "allocated"
    if name.endswith(" (deleted-realloc)"):
        name, deleted = name[:-18], "reallocated"
    elif name.endswith(" (deleted)"):
        name, deleted = name[:-10], "deleted"
    category, priority = classify(name, deleted)
    ident = "E" + hashlib.sha256((volume + "\0" + inode + "\0" + name).encode()).hexdigest()[:20]
    length = int(size)
    if length < 0:
        raise ValueError("Negative file size")
    return {"id": ident, "volume": volume, "inode": inode, "path": name, "size": length,
            "deleted": deleted, "category": category, "priority": priority,
            "metadata": json.dumps({"mode": mode, "uid": uid, "gid": gid,
                                    "atime": int(atime), "mtime": int(mtime), "ctime": int(ctime), "crtime": int(crtime)})}


def inventory(store, image, config, layout):
    required = ("fsstat", "fls", "icat")
    if not all(available(name) for name in required):
        store.stage("filesystem", "unavailable", "Install sleuthkit for filesystem inventory and recovery")
        for volume in store.volumes():
            volume["filesystem_status"] = "unavailable"
            store.volume(volume)
        return
    ss = layout["sector_size"]
    for volume in store.volumes():
        ident = volume["id"]
        stage = "inventory:" + ident
        if store.done(stage):
            continue
        if volume["signature"] in ("luks-encrypted", "bitlocker-encrypted", "lvm-container", "apfs-container"):
            volume["filesystem_status"] = "needs-unlocking-or-container-support"
            store.volume(volume)
            store.stage(stage, "unsupported", volume["signature"])
            continue
        log(f"Inspecting filesystem {ident} at byte {volume['start']}")
        args = ["-b", str(ss), "-o", str(volume["start"] // ss), "-i", "raw", str(image)]
        output = store.root / "logs" / (ident + ".fsstat.txt")
        code, reason = run_file(["fsstat", "-t", *args], output, store.root / "logs" / (ident + ".fsstat.stderr"), timeout=60, max_bytes=1024**2)
        if code or reason:
            volume["filesystem_status"] = "unreadable-or-unsupported"
            store.volume(volume)
            store.stage(stage, "unsupported", "Filesystem probe failed; see private tool logs")
            continue
        volume["filesystem"] = output.read_text(errors="replace").strip()[:100]
        body = store.root / "private" / (ident + ".bodyfile")
        store.stage(stage, "running", "Enumerating filesystem records")
        code, reason = run_file(["fls", "-r", "-p", "-m", "/", *args], body,
                               store.root / "logs" / (ident + ".fls.stderr"),
                               timeout=config["tool_timeout"], max_bytes=512 * 1024**2)
        count = rejected = 0
        with body.open(errors="replace") as stream:
            for line in stream:
                try:
                    row = parse_bodyfile(line, ident)
                except ValueError:
                    rejected += 1
                    continue
                store.file(row)
                source = {"method": "filesystem-path", "volume": ident, "file_id": row["id"],
                          "path": row["path"], "inode": row["inode"], "deleted": row["deleted"]}
                for hit in path_hits(row["path"]):
                    store.finding(hit, source)
                count += 1
                if config["max_files"] and count >= config["max_files"]:
                    reason = "File inventory limit reached; increase --max-files and resume"
                    break
                if count % 1000 == 0:
                    store.db.commit()
        status = "partial" if code or reason or rejected else "complete"
        volume["filesystem_status"] = status
        volume["file_records"] = count
        store.volume(volume)
        store.stage(stage, status, f"{count} records; {rejected} unparsed rows. {reason}. Deleted-directory traversal depends on filesystem/TSK support.")
    recover_files(store, image, config, layout)


def output_usage(store):
    # Count artifacts once; keep the budget independent of hardlinks/duplicate records.
    return sum(path.stat().st_size for path in (store.root / "artifacts").iterdir() if path.is_file())


def pending_files(store):
    """Keyset pagination keeps uncapped inventories from becoming a giant list."""
    last = (-1,-1,"")
    while True:
        rows = store.db.execute("""SELECT * FROM files WHERE inode IS NOT NULL
            AND status NOT IN ('exported','metadata-only') AND (priority,size,id) > (?,?,?)
            ORDER BY priority,size,id LIMIT 256""",last).fetchall()
        if not rows:
            return
        for row in rows:
            yield row
        last = (rows[-1]["priority"],rows[-1]["size"],rows[-1]["id"])


def recover_files(store, image, config, layout):
    store.stage("filesystem", "running", "Exporting selected files and scanning their contents")
    # Refresh older cases' priorities, including deleted history databases. Retry
    # previously unclassified history/deleted files without rescanning raw bytes.
    for row in store.db.execute("SELECT id,path,deleted,status,detail FROM files"):
        category, priority = classify(row["path"], row["deleted"])
        store.db.execute("UPDATE files SET category=?,priority=? WHERE id=?", (category, priority, row["id"]))
        if category != "other" and row["status"] == "metadata-only" and (row["detail"] or "").startswith("Unclassified file"):
            store.db.execute("UPDATE files SET status='pending' WHERE id=?", (row["id"],))
    store.db.commit()
    volumes = {v["id"]: v for v in store.volumes()}
    used = output_usage(store)
    known_artifacts = {str(p.relative_to(store.root)) for p in (store.root / "artifacts").iterdir()}
    total = store.db.execute("SELECT count(*) FROM files WHERE inode IS NOT NULL AND status NOT IN ('exported','metadata-only')").fetchone()[0]
    for index, row in enumerate(pending_files(store)):
        metadata = json.loads(row["metadata"])
        # Export regular files. Links/directories remain metadata, never recreated on disk.
        mode = metadata["mode"]
        if not (mode.startswith("r") or mode.startswith("-")) or row["size"] == 0:
            store.file_status(row["id"], "metadata-only", "Non-regular or empty file")
            continue
        if row["category"] == "other" and row["size"] > 2 * 1024**2:
            store.file_status(row["id"], "metadata-only", "Unclassified file over 2 MiB; raw image still scanned")
            continue
        if row["size"] > config["max_file_bytes"]:
            store.file_status(row["id"], "skipped-limit", "Per-file export limit")
            continue
        if used + row["size"] > config["max_output_bytes"]:
            store.file_status(row["id"], "skipped-limit", "Case export budget reached")
            continue
        volume = volumes[row["volume"]]
        argv = ["icat", "-b", str(layout["sector_size"]), "-o", str(volume["start"] // layout["sector_size"]), "-i", "raw"]
        if row["deleted"] != "allocated":
            argv.append("-r")
        argv += [str(image), row["inode"]]
        temp = store.root / "private" / "export.part"
        error = store.root / "logs" / (row["id"] + ".icat.stderr")
        code, reason = run_file(argv, temp, error, timeout=300,
                               max_bytes=min(config["max_file_bytes"], row["size"] + 1))
        length = temp.stat().st_size
        if length == 0:
            temp.unlink()
            store.file_status(row["id"], "error", "No content exported; see icat log")
            continue
        target, digest = artifact(store, temp, identify_extension(temp, Path(row["path"]).suffix))
        source = {"method": "filesystem-content", "volume": row["volume"], "file_id": row["id"],
                  "path": row["path"], "inode": row["inode"], "artifact": target, "deleted": row["deleted"]}
        analyze_artifact(store, store.root / target, source, config)
        status = "partial" if code or reason or length != row["size"] else "exported"
        detail = reason or ("Exported bytes match metadata size; original integrity not proven" if status == "exported" else "Export differs from filesystem record")
        store.file_status(row["id"], status, detail, target, digest)
        if target not in known_artifacts:
            used += length
            known_artifacts.add(target)
        if index % 50 == 0:
            log(f"File recovery: {index + 1}/{total} selected records")
    issues = store.db.execute("SELECT count(*) FROM files WHERE status IN ('skipped-limit','error','partial')").fetchone()[0]
    unsupported = any(v["filesystem_status"] != "complete" for v in store.volumes())
    store.stage("filesystem", "partial" if issues or unsupported else "complete",
                f"{issues} files skipped by limits or incompletely exported. See inventory stages for volume coverage.")


def carve(store, image, config):
    if store.done("carving"):
        return
    if config["carve"] == "off":
        store.stage("carving", "disabled", "PhotoRec carving disabled by operator")
        return
    if not available("photorec"):
        store.stage("carving", "unavailable", "Install testdisk for PhotoRec media/deleted-content recovery")
        return
    carved = store.root / "private" / "photorec"
    carved.mkdir(exist_ok=True, mode=0o700)
    # Resume existing exports by importing them; never discard recovered material.
    ingest_carved(store, carved, config)
    remaining = config["max_output_bytes"] - output_usage(store)
    if remaining <= 0:
        store.stage("carving", "partial", "No export budget remains")
        return
    log("PhotoRec: carving the whole image, including gaps and damaged filesystem areas")
    store.stage("carving", "running", "PhotoRec whole-image signature carving")
    last_check = 0
    def monitor():
        nonlocal last_check
        if time.monotonic() - last_check < 2:
            return None
        last_check = time.monotonic()
        usage = sum(p.stat().st_size for p in carved.rglob("*") if p.is_file())
        if usage >= remaining:
            return "PhotoRec reached export budget (checked every 2 seconds; temporary overshoot possible)"
        if shutil.disk_usage(store.root).free < 256 * 1024**2:
            return "Less than 256 MiB free; stopped carving"
        return None
    command = ["photorec", "/log", "/d", str(carved / "recup"), "/cmd", str(image),
               "partition_none,fileopt,everything,enable,wholespace,search"]
    code, reason = run_file(command, store.root / "logs" / "photorec.stdout", store.root / "logs" / "photorec.stderr",
                           cwd=carved, timeout=config["tool_timeout"], max_bytes=config["max_file_bytes"], monitor=monitor)
    ingest_carved(store, carved, config)
    store.stage("carving", "partial" if code or reason else "complete",
                reason or ("PhotoRec exited with an error; see logs" if code else "Whole-image carving finished; file integrity and deletion status require review"))


def ingest_carved(store, directory, config):
    def scan_export(row):
        metadata = json.loads(row["metadata"])
        source = {"method": "photorec", "file_id": row["id"], "artifact": row["artifact"], "path": row["path"],
                  "deleted": "unknown", "extents": metadata.get("extents", []), "volumes": metadata.get("volumes", []),
                  "provenance_note": "Byte extents from PhotoRec report.xml when available; filenames are never used to guess offsets"}
        analyze_artifact(store, store.root / row["artifact"], source, config)
        store.file_status(row["id"], "exported", "Carved candidate; integrity unverified", row["artifact"], row["sha256"])

    for row in list(store.db.execute("SELECT * FROM files WHERE inode IS NULL AND status='scanning' AND artifact IS NOT NULL")):
        scan_export(row)
    provenance = {}
    image_size = store.get("image", {}).get("size", 0)
    for report in directory.glob("recup.*/report.xml"):
        if report.stat().st_size > 64 * 1024**2:
            continue
        try:
            for _, element in ET.iterparse(report, events=("end",)):
                if element.tag.rsplit("}", 1)[-1] != "fileobject":
                    continue
                filename = None
                runs = []
                for item in element.iter():
                    tag = item.tag.rsplit("}", 1)[-1]
                    if tag == "filename":
                        filename = Path(item.text or "").name
                    elif tag == "byte_run":
                        try:
                            offset, length, logical = int(item.attrib["img_offset"]), int(item.attrib["len"]), int(item.attrib.get("offset", "0"))
                            if offset >= 0 and length > 0 and logical >= 0 and offset + length <= image_size:
                                runs.append({"image_offset": offset, "file_offset": logical, "length": length})
                        except (KeyError, ValueError):
                            pass
                if filename and runs:
                    provenance[(str(report.parent), filename)] = runs
                element.clear()
        except (ET.ParseError, OSError):
            # Interrupted carving may leave an unfinished report. Already parsed
            # records remain usable; missing mappings are explicitly unknown.
            continue
    for path in sorted(directory.glob("recup.*/*")):
        if not path.is_file() or path.name == "report.xml":
            continue
        relative = str(path.relative_to(store.root))
        ident = "E" + hashlib.sha256(relative.encode()).hexdigest()[:20]
        existing = store.db.execute("SELECT status FROM files WHERE id=?", (ident,)).fetchone()
        if existing and existing[0] == "exported":
            continue
        length = path.stat().st_size
        category, priority = classify(path.name)
        extents = provenance.get((str(path.parent), path.name), [])
        disk_offset = next((run["image_offset"] for run in extents if run["file_offset"] == 0), None)
        matched_volumes = locate(store.volumes(), disk_offset) if disk_offset is not None else []
        store.file({"id": ident, "volume": None, "inode": None, "path": path.name, "size": length,
                    "deleted": "unknown", "category": category, "priority": priority,
                    "metadata": json.dumps({"origin": "photorec", "carved_name": path.name,
                                            "extents": extents, "volumes": matched_volumes})})
        target, digest = artifact(store, path, identify_extension(path, path.suffix))
        store.file_status(ident, "scanning", "Carved content awaiting crypto inspection", target, digest)
        scan_export(store.db.execute("SELECT * FROM files WHERE id=?", (ident,)).fetchone())
    store.db.commit()


def bulk_scan(store, image, config):
    if store.done("bulk_extractor"):
        return
    if not config["bulk"]:
        store.stage("bulk_extractor", "disabled", "Optional bulk_extractor pass not requested")
        return
    if not available("bulk_extractor"):
        store.stage("bulk_extractor", "unavailable", "bulk_extractor not installed")
        return
    target = store.root / "private" / ("bulk-" + str(int(time.time())))
    store.stage("bulk_extractor", "running", "Optional raw feature extraction")
    log("Running optional bulk_extractor pass")
    limit = config["max_output_bytes"] - output_usage(store)
    def monitor():
        if target.exists() and sum(p.stat().st_size for p in target.rglob("*") if p.is_file()) > limit:
            return "bulk_extractor output budget reached"
        return None
    code, reason = run_file(["bulk_extractor", "-o", str(target), str(image)],
                           store.root / "logs" / "bulk.stdout", store.root / "logs" / "bulk.stderr",
                           timeout=config["tool_timeout"], max_bytes=config["max_file_bytes"], monitor=monitor)
    store.stage("bulk_extractor", "partial" if code or reason else "complete",
                reason or "Native feature files retained privately; not merged into crypto findings")


def completion_status(store):
    required = [store.stage_row(name).get("status") for name in
                ("raw", "filesystem", "carving", "browser_history", "enrichment")]
    if store.get("config", {}).get("bulk"):
        required.append(store.stage_row("bulk_extractor").get("status"))
    return "complete" if all(state == "complete" for state in required) else "complete-with-gaps"


def validate_config(config):
    if config["hash_mode"] not in ("quick", "full"):
        raise ValueError("hash_mode must be quick or full")
    if config["max_files"] < 0:
        raise ValueError("max_files must be zero (unlimited) or positive")
    for key in ("chunk_size", "max_file_bytes", "max_output_bytes", "tool_timeout", "max_browser_rows"):
        if config[key] <= 0:
            raise ValueError(f"{key} must be positive")
    if config["chunk_size"] < 4096:
        raise ValueError("Chunk size must be at least 4096 bytes")


def scan(image: Path, root: Path, overrides: dict, resume=False, *, allow_partial=False, tool_report=None):
    if not image.is_file() or image.stat().st_size == 0:
        raise ValueError("Input must be a nonempty regular raw image file")
    if image == root or root in image.parents:
        raise ValueError("Input image must live outside the output case directory")
    existing = (root / "case.sqlite").exists()
    if not existing and any(p.name != ".lock" for p in root.iterdir()):
        raise ValueError("New case output must be empty to avoid overwriting existing files")
    if existing and not resume:
        raise ValueError("Case already exists; use --resume, --restart, or a new output directory")
    if resume and not existing:
        raise ValueError("Cannot resume a case that does not exist")
    # Read saved settings without opening the writable Store. A failed preflight
    # must preserve the previous case and must precede even full-image hashing.
    old_config = {}
    if existing:
        db = sqlite3.connect((root / "case.sqlite").resolve().as_uri() + "?mode=ro", uri=True)
        try:
            row = db.execute("SELECT value FROM meta WHERE key='config'").fetchone()
            old_config = (json.loads(row[0]) or {}) if row else {}
        finally:
            db.close()
    config = {**DEFAULTS, **old_config, **overrides}
    # File-count limits are now opt-in per invocation, including for old cases.
    config["max_files"] = overrides.get("max_files", 0)
    validate_config(config)
    if tool_report is None:
        tool_report = check_dependencies(config, allow_partial=allow_partial)
    store = Store(root)
    try:
        previous = store.get("image")
        if existing and not previous:
            # Versions before hash_mode saved identity/config only after the
            # initial hash finished. A Ctrl-C there leaves an empty case shell.
            started = any(store.db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
                          for table in ("stages", "volumes", "files", "findings", "occurrences", "browser_history"))
            if started:
                raise ValueError("Case has analysis data but no source identity; use a new case")
        if previous:
            if config["sector_size"] != old_config.get("sector_size"):
                raise ValueError("Changing sector size requires a new case")
            if store.get("version") != __version__:
                raise ValueError("Scanner version changed; use a new case to avoid incompatible checkpoints")
        before = image.stat()
        if not previous:
            # Save a resumable baseline before potentially lengthy full hashing.
            store.put("image", dict(stat_identity(before), path=str(image), sha256=None,
                                    hash_mode=config["hash_mode"], sha256_status="pending"))
        store.put("config", config)
        store.put("version", __version__)
        store.put("status", "running")
        store.stage("identity", "running", f"Checking source identity using {config['hash_mode']} mode")
        try:
            identity = verify_image(image, before, previous, config["hash_mode"])
        except ValueError as exc:
            store.stage("identity", "failed", str(exc))
            store.put("status", "source-changed")
            raise
        store.put("image", identity)
        store.stage("identity", "complete", "Metadata check only; image SHA-256 not recomputed" if config["hash_mode"] == "quick"
                    else "Full image SHA-256 " + identity["sha256_status"])
        store.put("tools", tool_report)
        if not store.done("layout"):
            layout = discover(image, config["sector_size"])
            for volume in layout["volumes"]:
                store.volume(volume)
            store.put("layout", layout)
            store.stage("layout", "complete", f"{len(layout['volumes'])} volume candidates; {layout['scheme']}")
        layout = store.get("layout")
        write_report(store)
        # Raw crypto scanning includes all partitions and unallocated regions early.
        if not store.done("raw"):
            log("Scanning raw image for crypto and interesting-content indicators")
            scan_stream(store, image, {"method": "raw"}, raw=True, chunk_size=config["chunk_size"], stage="raw")
        audit(store, image)
        write_report(store)
        inventory(store, image, config, layout)
        # Publish filesystem history before the potentially long carving pass.
        extract_history(store, config["max_browser_rows"])
        write_report(store)
        carve(store, image, config)
        extract_history(store, config["max_browser_rows"])
        enrich(store, config)
        bulk_scan(store, image, config)
        after = image.stat()
        if stat_identity(before) != stat_identity(after):
            store.put("status", "source-changed")
            raise ValueError("Source changed during scanning; findings cannot be treated as a consistent snapshot")
        status = completion_status(store)
        store.put("status", status)
        write_report(store)
        log(f"{status}: {root / 'report.html'}")
        return 0 if status == "complete" else 2
    except KeyboardInterrupt:
        store.put("status", "interrupted")
        if store.stage_row("identity").get("status") == "running":
            store.stage("identity", "interrupted", "Source check interrupted; no analysis started in this run")
        write_report(store)
        log("Interrupted. Findings saved; rerun with --resume.")
        return 130
    except Exception:
        if store.get("status") == "running":
            store.put("status", "failed")
        write_report(store)
        raise
    finally:
        store.close()
