"""Static offline dashboard, chunked inventory explorer, and media navigation."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from .report import clean, esc, page
from .triage import assessment
from .util import atomic_write

IMAGES = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic", ".heif", ".dng", ".cr2", ".nef"}
VIDEOS = {".mp4", ".mov", ".avi", ".mkv", ".mpg", ".mpeg", ".m4v", ".webm", ".3gp"}


def js_value(value):
    # JSON is data even when loaded via a file:// script tag. Escape HTML tokens.
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def safe_asset(value):
    return value if isinstance(value,str) and re.fullmatch(r"(?:artifacts/[0-9a-f]{64}\.[a-zA-Z0-9]{1,8}|thumbnails/E[0-9a-f]{20}\.jpg)", value) else None


def write_js(path, target, data):
    atomic_write(path, (target + "=" + js_value(data) + ";\n").encode())


def inventory_data(store, directory):
    folders = {"root": {"id":"root", "parent":None, "name":"All volumes", "children":[], "chunks":[], "counts":{}, "dir_counts":{}}}
    media, chunk, chunk_number = [], [], 0
    total_counts = Counter()

    def folder(volume, parts):
        parent = "root"
        for i, name in enumerate([volume] + parts):
            key = "D" + hashlib.sha256(json.dumps([volume,parts[:i]]).encode()).hexdigest()[:20]
            if key not in folders:
                folders[key] = {"id":key,"parent":parent,"name":clean(name),"children":[],"chunks":[],"counts":{},"dir_counts":{}}
                folders[parent]["children"].append(key)
            parent = key
        return parent

    def flush():
        nonlocal chunk, chunk_number
        if chunk:
            write_js(directory / f"inventory-{chunk_number}.js", f"window.DA_CHUNKS[{chunk_number}]", chunk)
            chunk_number += 1
            chunk = []

    for row in store.db.execute("SELECT * FROM files ORDER BY volume,path,id"):
        meta = json.loads(row["metadata"])
        parts = [p for p in row["path"].replace("\\","/").split("/") if p]
        is_dir = meta.get("mode","").startswith("d")
        parent = folder(row["volume"] or "Unknown origin / carved", parts if is_dir else parts[:-1])
        state = row["deleted"] if row["deleted"] in ("allocated","deleted","reallocated") else "unknown"
        if not is_dir:
            total_counts[state] += 1
        current = parent
        while current is not None:
            counts = folders[current]["dir_counts" if is_dir else "counts"]
            counts[state] = counts.get(state,0) + 1
            current = folders[current]["parent"]
        if is_dir:
            continue
        item = {"id":row["id"], "folder":parent, "name":clean(parts[-1] if parts else row["path"]),
                "path":clean(row["path"]), "volume":row["volume"], "state":state, "size":row["size"],
                "category":row["category"], "status":row["status"], "detail":clean(row["detail"] or ""),
                "artifact":safe_asset(row["artifact"]), "thumbnail":None,
                "modified":meta.get("mtime"), "created":meta.get("crtime"),
                "sha256":row["sha256"], "inode":clean(row["inode"])}
        item["on_demand"] = bool(row["volume"] and re.fullmatch(r"\d+(?:-\d+){0,2}", row["inode"] or "") and meta.get("mode", "").startswith(("r", "-")))
        thumb = f"thumbnails/{row['id']}.jpg"
        if safe_asset(thumb) and (store.root / thumb).is_file():
            item["thumbnail"] = thumb
        suffix = Path(row["artifact"] or row["path"]).suffix.lower()
        if suffix in IMAGES | VIDEOS or "image" in meta:
            observed = meta.get("video", {}) if suffix in VIDEOS else meta.get("image", {})
            media.append(dict(item, type="video" if suffix in VIDEOS else "image",
                              width=observed.get("width"), height=observed.get("height"), duration=observed.get("duration")))
        if not folders[parent]["chunks"] or folders[parent]["chunks"][-1] != chunk_number:
            folders[parent]["chunks"].append(chunk_number)
        chunk.append(item)
        if len(chunk) == 2000:
            flush()
    flush()
    for value in folders.values():
        value["children"].sort(key=lambda ident:folders[ident]["name"].casefold())
    manifest = {"folders":folders,"chunk_count":chunk_number,"counts":dict(total_counts),"media_count":len(media),
                "volumes":{v["id"]:clean({"name":v.get("name",""),"filesystem":v.get("filesystem",v.get("signature",""))}) for v in store.volumes()}}
    write_js(directory / "inventory.js", "window.DA_INVENTORY", manifest)
    # Keep the gallery's navigation small: only media folders and their ancestors,
    # using the same stable IDs as the file explorer (including separate volumes).
    media_folder_ids = {"root"}
    for item in media:
        current = item["folder"]
        while current not in media_folder_ids:
            media_folder_ids.add(current)
            current = folders[current]["parent"]
    media_folders = {
        ident: {"id": ident, "parent": value["parent"], "name": value["name"],
                "children": [child for child in value["children"] if child in media_folder_ids]}
        for ident, value in folders.items() if ident in media_folder_ids
    }
    write_js(directory / "media-folders.js", "window.DA_MEDIA_FOLDERS",
             {"folders": media_folders, "volumes": manifest["volumes"]})
    write_js(directory / "media.js", "window.DA_MEDIA", media)
    return manifest, media


def navigation(active):
    links = [("report.html","Overview"),("crypto.html","Crypto"),("files.html","Files"),
             ("files.html#deleted","Deleted files"),("media.html","Photos & videos"),
             ("browser-history.html","Browser history"),("evidence.html","All observations"),("details.html","Coverage")]
    return "<nav class='nav'>" + "".join(f"<a {'aria-current=page' if name==active else ''} href='{url}'>{name}</a>" for url,name in links) + "</nav>"


def app_page(title, body, app, extra=""):
    return page("Cold Digger · " + title, navigation(title) + f"<h1>{esc(title)}</h1>" + body +
                f"<script src='dashboard-data/{app}.js'></script>" + extra +
                "<script src='dashboard-data/ui.js'></script>", "")


def write_dashboard(store, data):
    directory = store.root / "dashboard-data"
    directory.mkdir(exist_ok=True,mode=0o700)
    atomic_write(directory / "ui.js", Path(__file__).with_name("static").joinpath("ui.js").read_bytes())
    atomic_write(directory / "explorer.js", Path(__file__).with_name("static").joinpath("explorer.js").read_bytes())
    for name in ("access.js", "gallery.js"):
        atomic_write(directory / name, Path(__file__).with_name("static").joinpath(name).read_bytes())
    manifest, media = inventory_data(store,directory)
    audits = {r["finding_id"]:json.loads(r["data"]) for r in store.db.execute("SELECT * FROM crypto_assessments")}
    balances = [dict(r, data=json.loads(r["data"])) for r in store.db.execute("SELECT * FROM balances")]
    evidence = []
    for finding in data["findings"]:
        validation = audits.get(finding["id"],{})
        item = dict(finding, triage=assessment(finding,validation), automatic_validation=validation)
        for value in validation.get("addresses",[]):
            for balance in balances:
                same = balance["address"].lower() == value["address"].lower() if value["chain"] == "ethereum" else balance["address"] == value["address"]
                if balance["chain"] == value["chain"] and same and balance["status"] == "ok" and int(balance["data"].get("balance_base_units","0")) > 0:
                    item["triage"] = {"tier":"attention", "reason":"Provider reports funds at an associated public address; see validation for key linkage and lookup scope"}
        evidence.append(item)
    evidence.sort(key=lambda f:({"attention":0,"lead":1,"background":2}[f["triage"]["tier"]],f["id"]))
    counts = Counter(f["triage"]["tier"] for f in evidence)
    write_js(directory / "evidence.js", "window.DA_EVIDENCE", {"findings":evidence,"balances":balances})
    write_js(directory / "crypto.js", "window.DA_EVIDENCE", {"findings":[f for f in evidence if f["kind"] in audits or f["category"]=="crypto" or f["kind"]=="private_key_header"],"balances":balances})
    cards = [("Needs attention",counts["attention"],"crypto.html"),("Unconfirmed leads",counts["lead"],"crypto.html#lead"),
             ("Deleted files",manifest["counts"].get("deleted",0),"files.html#deleted"),
             ("Photos & videos",len(media),"media.html"),("History records",data["browser_history"]["records"],"browser-history.html")]
    body = [navigation("Overview"), "<div class='eyebrow'>DISK ANALYZER / LOCAL CASE</div><h1>Recovery overview</h1>",
            f"<p class='muted'>{esc(data['status'])} · {len(data['volumes'])} volumes · {data['file_count']:,} inventory records · {data['exported_count']:,} exports</p><div class='cards'>"]
    body += [f"<a class='card' href='{url}'><strong>{count:,}</strong>{label}</a>" for label,count,url in cards]
    body.append("</div><h2>What matters so far</h2>")
    if counts["attention"]:
        body.append(f"<p>{counts['attention']} key/wallet candidates passed supported local checks. Review their validation and balance status in <a href='crypto.html'>Crypto</a>.</p>")
    else:
        body.append("<p>No key or wallet has yet passed enough checks to appear in the attention list.</p>")
    body.append(f"<p>{counts['background']:,} keyword, filename, example or incidental observations are kept in <a href='evidence.html'>supporting evidence</a>.</p>")
    deleted_exports = store.db.execute("SELECT count(*) FROM files WHERE deleted='deleted' AND artifact IS NOT NULL").fetchone()[0]
    body.append(f"<p>{deleted_exports:,} deleted files have exported content. The gallery lists {sum(m['type']=='image' for m in media):,} images and {sum(m['type']=='video' for m in media):,} videos; {sum(bool(m['artifact']) for m in media):,} have saved exports.</p>")
    if data["browser_history"]["top_domains"]:
        body.append("<p>Most represented domains in recovered history: " + ", ".join(esc(d["domain"])+f" ({d['records']:,} records)" for d in data["browser_history"]["top_domains"][:5]) + ". Counts can include duplicate database copies.</p>")
    issues = [s for s in data["stages"] if s["status"] not in ("complete","disabled")]
    if issues:
        body.append("<p class='notice'>Recovery is incomplete: " + esc(", ".join(s["name"]+" ("+s["status"]+")" for s in issues)) + ". <a href='details.html'>View coverage and limits</a>.</p>")
    for f in [f for f in evidence if f["triage"]["tier"] != "background"][:8]:
        body.append(f"<article class='lead'><a href='crypto.html#{esc(f['id'])}'>{esc(f['title'])}</a><p>{esc(f['triage']['reason'])}</p><small>{esc(f['id'])} · {len(f['sources'])} source(s)</small></article>")
    body += ["<h2>Explore recovered content</h2><div class='cards'>",
             "<a class='card' href='files.html'>Browse original folders<br><small>Available files and their recovery status</small></a>",
             "<a class='card' href='files.html#deleted'>Browse deleted folders<br><small>Paths reconstructed from surviving metadata</small></a>",
             "<a class='card' href='files.html#unknown'>Browse carved files<br><small>Original paths and deletion state unknown</small></a></div>",
             "<h2>Local AI notes</h2>"]
    for analysis in data["ai_analyses"]:
        for claim in analysis.get("claims",[]):
            body.append(f"<p><strong>{esc(claim['title'])}</strong> · {esc(claim['type'])}<br>{esc(claim['explanation'])}</p>")
    if not data["ai_analyses"]:
        body.append("<p class='muted'>No local AI notes yet. Automatic validation and evidence ranking run independently.</p>")
    body.append(f"<details><summary>Source identity & exports</summary><p><code>{esc(data['image'].get('path',''))}</code></p><p>SHA-256: <code>{esc(data['image'].get('sha256') or 'Not computed')}</code></p><a href='findings.json'>JSON</a> · <a href='inventory.csv'>Inventory CSV</a></details>")
    atomic_write(store.root / "report.html",page("Cold Digger · Recovery overview","".join(body)))
    controls = "<div class='toolbar'><input id='search' type='search' aria-label='Search' placeholder='Search names, types or evidence IDs'><select id='tier' aria-label='Evidence tier'><option value='attention'>Needs attention</option><option value='lead'>Unconfirmed leads</option><option value='background'>Background</option><option value='all'>All observations</option></select></div><p id='summary' aria-live='polite'></p><div id='results'></div><div id='pagination' class='toolbar'></div>"
    atomic_write(store.root / "crypto.html",app_page("Crypto", "<p>Keys stay private. Supported structures, checksums and derived public addresses are checked locally. Funds remain unknown until you run an explicit balance lookup.</p>"+controls,"crypto"))
    atomic_write(store.root / "evidence.html",app_page("All observations", "<p>All retained detections, including weak matches and likely examples. Nothing is discarded by dashboard ranking.</p>"+controls,"evidence"))
    from .explorer import file_browser_page
    from .gallery import media_browser_page
    atomic_write(store.root / "files.html",file_browser_page(navigation("Files")))
    atomic_write(store.root / "media.html",media_browser_page(navigation("Photos & videos")))
    data["triage_summary"] = dict(counts)
    data["crypto_validation"] = audits
    data["balances"] = balances
