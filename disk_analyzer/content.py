from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import time
import zipfile

from .detect import Hit, OVERLAP, scan_bytes, structured_hits
from .browser import history_name
from .layout import locate
from .process import available, run_file
from .util import atomic_write, digest_file, log

MEDIA = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".tif", ".tiff", ".bmp", ".dng", ".cr2", ".nef",
         ".mp4", ".mov", ".avi", ".mkv", ".mpg", ".mpeg", ".m4v", ".webm", ".3gp", ".mp3", ".wav", ".flac"}
DOCUMENTS = {".txt", ".md", ".json", ".csv", ".xml", ".html", ".htm", ".log", ".pdf", ".doc", ".docx", ".odt", ".rtf", ".xls", ".xlsx", ".eml", ".mbox", ".sql", ".sqlite", ".db", ".zip", ".7z", ".tar", ".gz", ".kdbx", ".key", ".pem", ".asc", ".conf", ".ini", ".py", ".sh", ".js", ".ts"}
WALLET_PATH = re.compile(r"(?:wallet|electrum|bitcoin|litecoin|dogecoin|monero|metamask|exodus|keystore|nkbihfbeogaeaoehlefnkodbefgpgknn|seed|mnemonic|\.keys$)", re.I)
INTERESTING_PATHS = [(r"(?:\.git/|\.git$)", "Source repository metadata"),
                     (r"(?:history|places\.sqlite|bookmarks)", "Browser or command-history artifact"),
                     (r"(?:backup|windowsimagebackup|mobile.?sync|time.?machine)", "Backup artifact"),
                     (r"(?:\.kdbx$|\.hc$|\.tc$)", "Password database or encrypted-container candidate")]


def classify(path, deleted="unknown"):
    suffix = Path(path).suffix.lower()
    if WALLET_PATH.search(path):
        return "crypto", 0
    # Recover history databases/sidecars before large media consumes the budget.
    if history_name(path):
        return "browser", 1
    if suffix in MEDIA:
        return "media", 2
    if deleted in ("deleted", "reallocated"):
        return "deleted", 3
    if suffix in DOCUMENTS:
        return "interesting", 4
    return "other", 5


def path_hits(path):
    if WALLET_PATH.search(path):
        yield Hit("wallet_path", "Wallet or recovery-related filename", path.encode("utf-8", "replace"), 0, 0,
                  validation="Filename/path indicator only; contents may be unrelated")
    for pattern, title in INTERESTING_PATHS:
        if re.search(pattern, path, re.I):
            yield Hit("interesting_path", title, path.encode("utf-8", "replace"), 0, 0, category="interesting")


def scan_stream(store, path, source, *, raw=False, chunk_size=4 * 1024**2, stage=None):
    size = path.stat().st_size
    cursor = store.stage_row(stage).get("progress", 0) if stage else 0
    last_log = time.monotonic()
    if cursor > size:
        raise ValueError("Invalid scan checkpoint")
    with path.open("rb") as stream:
        while cursor < size:
            start = max(0, cursor - OVERLAP)
            end = min(size, cursor + chunk_size)
            stream.seek(start)
            data = stream.read(end - start + OVERLAP)
            for hit in scan_bytes(data):
                offset = start + hit.start
                if not cursor <= offset < end:
                    continue
                origin = dict(source, length=hit.end - hit.start)
                if raw:
                    origin.update(image_offset=offset, volumes=locate(store.volumes(), offset), deleted="unknown")
                else:
                    origin.update(file_offset=offset)
                    if "transform" not in source:
                        for extent in source.get("extents", []):
                            if extent["file_offset"] <= offset and offset + hit.end - hit.start <= extent["file_offset"] + extent["length"]:
                                origin["image_offset"] = extent["image_offset"] + offset - extent["file_offset"]
                                break
                store.finding(hit, origin)
            cursor = end
            if stage:
                store.stage(stage, "running", f"Scanned {cursor} / {size} bytes", cursor)
                if time.monotonic() - last_log >= 15:
                    log(f"{stage}: {cursor:,}/{size:,} bytes scanned")
                    last_log = time.monotonic()
            else:
                store.db.commit()
    if stage:
        store.stage(stage, "complete", f"Scanned {size} bytes; raw hits have unknown allocation/deletion status", size)


def artifact(store, temp, suffix=".bin"):
    digest = digest_file(temp)
    suffix = suffix.lower() if re.fullmatch(r"\.[a-zA-Z0-9]{1,8}", suffix) else ".bin"
    target = f"artifacts/{digest}{suffix}"
    if (store.root / target).exists():
        temp.unlink()
    else:
        temp.replace(store.root / target)
    return target, digest


def identify_extension(path, fallback=".bin"):
    with path.open("rb") as stream:
        data = stream.read(32)
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    if data.startswith(b"%PDF-"):
        return ".pdf"
    if data.startswith(b"PK\x03\x04"):
        return ".zip"
    if data[4:8] == b"ftyp":
        return ".mp4"
    return fallback


def analyze_artifact(store, path, source, config):
    scan_stream(store, path, source, chunk_size=config["chunk_size"])
    if path.stat().st_size <= 8 * 1024**2:
        for hit in structured_hits(path.read_bytes()):
            store.finding(hit, dict(source, file_offset=0, length=path.stat().st_size))
    store.db.commit()


def enrich(store, config):
    store.stage("enrichment", "running", "Local text extraction, bounded ZIP inspection and optional image metadata")
    rows = list(store.db.execute("SELECT * FROM files WHERE artifact IS NOT NULL ORDER BY priority,id"))
    errors = []
    options = json.dumps({"ocr": config["ocr"], "tools": store.get("tools", {})}, sort_keys=True)
    for index, row in enumerate(rows):
        revision = hashlib.sha256((options + str(row["sha256"])).encode()).hexdigest()[:12]
        stage = "enrich:" + row["id"] + ":" + revision
        if store.done(stage):
            continue
        path = store.root / row["artifact"]
        source = {"method": "content", "file_id": row["id"], "volume": row["volume"], "path": row["path"],
                  "artifact": row["artifact"], "deleted": row["deleted"]}
        suffix = identify_extension(path, Path(row["path"]).suffix.lower())
        status = "complete"
        try:
            if suffix == ".zip":
                inspect_zip(store, path, source, config)
            if suffix == ".pdf" and available("pdftotext"):
                extract_text(store, path, source, ["pdftotext", "-layout", str(path)], ".pdf", config)
            if suffix in (".jpg", ".png", ".gif", ".webp", ".tiff", ".bmp"):
                image_metadata(store, path, source, row)
                if config["ocr"] and available("tesseract"):
                    extract_text(store, path, source, ["tesseract", str(path)], ".ocr", config)
        except Exception as exc:
            # A corrupt optional document/image must not abort the rest of a case.
            # Preserve the error type, mark this file partial, and retry on resume.
            errors.append({"file_id": row["id"], "error": type(exc).__name__})
            status = "partial"
        store.stage(stage, status, "Enrichment attempted; see enrichment notes for per-file limitations")
        if index % 100 == 0:
            log(f"Enrichment: {index + 1}/{len(rows)} exported files")
    notes = {"errors": errors, "ocr_enabled": config["ocr"], "ocr_available": bool(available("tesseract")),
             "pdf_available": bool(available("pdftotext")),
             "limits": "ZIP entries: 200, 8 MiB each, 32 MiB per archive, no recursive expansion. Text outputs: 8 MiB. Other archive types are not unpacked."}
    store.put("enrichment", notes)
    store.stage("enrichment", "partial" if errors else "complete", json.dumps(notes))


def inspect_zip(store, path, source, config):
    # No extraction to member-provided paths and no execution of archive contents.
    total = 0
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        skipped = 0
        for entry in infos[:200]:
            if entry.is_dir():
                continue
            if entry.flag_bits & 1 or entry.file_size > 8 * 1024**2 or total + entry.file_size > 32 * 1024**2:
                skipped += 1
                continue
            try:
                with archive.open(entry) as stream:
                    data = stream.read(8 * 1024**2 + 1)
                if len(data) > 8 * 1024**2:
                    skipped += 1
                    continue
            except (RuntimeError, NotImplementedError, OSError, zipfile.BadZipFile):
                skipped += 1
                continue
            total += len(data)
            origin = dict(source, method="zip-member", member=entry.filename)
            for hit in scan_bytes(data):
                store.finding(hit, dict(origin, member_offset=hit.start, length=hit.end - hit.start))
            for hit in structured_hits(data):
                store.finding(hit, origin)
            # XML word-processing text can have a tag between every seed word.
            if entry.filename.endswith(".xml"):
                text = re.sub(rb"<[^>]{0,4096}>", b" ", data)
                for hit in scan_bytes(text):
                    store.finding(hit, dict(origin, transform="xml-tags-removed", text_offset=hit.start))
        if skipped or len(infos) > 200:
            store.finding(Hit("archive_limit", "Archive partly inspected", b"zip-inspection-limits", 0, 0,
                              validation="Some ZIP members were encrypted, unsupported, or exceeded inspection limits", category="interesting"), source)
    store.db.commit()


def extract_text(store, path, source, command, kind, config):
    ident = source["file_id"]
    target = store.root / "private" / (ident + kind + ".txt")
    error = store.root / "logs" / (ident + kind + ".stderr")
    if kind == ".pdf":
        code, reason = run_file(command + ["-"], target, error, timeout=120, max_bytes=8 * 1024**2)
    else:
        code, reason = run_file(command + ["stdout"], target, error, timeout=120, max_bytes=8 * 1024**2)
    if target.exists() and target.stat().st_size:
        scan_stream(store, target, dict(source, method="ocr" if kind == ".ocr" else "pdf-text",
                    text_artifact=str(target.relative_to(store.root)), transform="text extraction; offsets are in text output"),
                    chunk_size=config["chunk_size"])
    if code or reason:
        raise RuntimeError("Text extraction incomplete")


def image_metadata(store, path, source, row):
    try:
        from PIL import Image
    except ImportError:
        return
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(path) as picture:
            metadata = {"width": picture.width, "height": picture.height, "format": picture.format}
            exif = picture.getexif()
            metadata["exif"] = {str(k): str(exif[k])[:1024] for k in (271, 272, 306, 36867) if k in exif}
            picture.thumbnail((320, 240))
            picture.convert("RGB").save(store.root / "thumbnails" / (row["id"] + ".jpg"))
            # Metadata and thumbnails stay local. Embedded dates are observations, not a trusted timeline.
            current = json.loads(row["metadata"])
            current["image"] = metadata
            store.db.execute("UPDATE files SET metadata=? WHERE id=?", (json.dumps(current), row["id"]))
            store.db.commit()


def prepare_media(store):
    """Prepare photo thumbnails and video posters using existing exports only."""
    from .preview import create_preview, IMAGES, VIDEOS
    from importlib.util import find_spec
    kinds = {Path(row[0]).suffix.lower() for row in store.db.execute("SELECT path FROM files WHERE artifact IS NOT NULL")}
    if kinds & IMAGES and find_spec("PIL") is None:
        raise ValueError("Install Pillow (Ubuntu python3-pil) to generate photo thumbnails")
    if kinds & VIDEOS and (not available("ffmpeg") or not available("ffprobe")):
        raise ValueError("Install FFmpeg (Ubuntu ffmpeg) to generate video posters")
    count = errors = 0
    store.stage("media", "running", "Preparing photo thumbnails and video posters")
    for row in store.db.execute("SELECT * FROM files WHERE artifact IS NOT NULL"):
        path = (store.root / row["artifact"]).resolve()
        if store.root.resolve() not in path.parents:
            continue
        suffix = Path(row["path"]).suffix.lower()
        if suffix not in IMAGES | VIDEOS:
            continue
        target = store.root / "thumbnails" / (row["id"] + ".jpg")
        if target.is_file():
            continue
        try:
            kind = "video" if suffix in VIDEOS else "image"
            observed = create_preview(path, target, kind)
            metadata = json.loads(row["metadata"])
            metadata[kind] = {**metadata.get(kind, {}), **observed}
            store.db.execute("UPDATE files SET metadata=? WHERE id=?", (json.dumps(metadata), row["id"]))
            count += 1
        except Exception:
            target.unlink(missing_ok=True)
            errors += 1
    store.db.commit()
    store.stage("media", "partial" if errors else "complete",
                f"{count} previews generated; {errors} unsupported or unreadable media files. Originals retained.")
    return 2 if errors else 0
