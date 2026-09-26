from __future__ import annotations

import csv
import html
import io
import json
import os
from urllib.parse import unquote, urlsplit, urlunsplit

from .detect import redact
from .util import atomic_json, atomic_write


def clean(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        # These values are generated identifiers/paths, never recovered secret text.
        identifiers = {"sha256", "fingerprint", "model_digest", "artifact", "secret_path", "text_artifact"}
        return {key: item if key in identifiers else clean(item) for key, item in value.items()}
    if isinstance(value, list):
        return [clean(item) for item in value]
    return value


def esc(value):
    return html.escape(str(value), quote=True)


STYLE = """
:root{color-scheme:light dark;font-family:system-ui,sans-serif;font-size:15px}
body{margin:0;background:#101820;color:#e7edf2}main{max-width:1350px;margin:auto;padding:32px}
h1{font-size:2rem;margin-bottom:8px}h2{margin-top:38px;color:#a3d8d0}p{line-height:1.6}
a{color:#84cec3}code{overflow-wrap:anywhere}small,.muted{color:#acbbc6}
.cards{display:flex;gap:14px;flex-wrap:wrap}.card{padding:18px;background:#1b2934;border-radius:9px;min-width:150px}
.card strong{display:block;font-size:1.6rem}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:.9rem}
td,th{padding:11px;text-align:left;border-bottom:1px solid #354550;vertical-align:top;overflow-wrap:anywhere}
th{color:#a3d8d0}details{max-width:650px}pre{white-space:pre-wrap;font-size:.8rem}
input{padding:12px;width:min(90%,650px);background:#1b2934;border:1px solid #60727d;color:inherit;border-radius:6px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:18px}.grid figure{margin:0;background:#1b2934;padding:12px}
img{max-width:100%;height:200px;object-fit:contain}.notice{border-left:4px solid #e8b767;padding-left:15px}
.nav{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:35px;border-bottom:1px solid #354550;padding-bottom:18px}.nav a{padding:8px;text-decoration:none}.nav a[aria-current]{background:#26443f;border-radius:6px;color:#c7f6df}
.eyebrow{letter-spacing:.15em;color:#92a9b6;font-size:.75rem}.card{text-decoration:none;border:1px solid #354550;flex:1}.card:hover{border-color:#84cec3}
.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:12px;margin:18px 0}.toolbar input[type=checkbox]{width:auto}.toolbar input[type=search]{max-width:420px}
button,select{padding:10px 14px;background:#1b2934;border:1px solid #60727d;color:inherit;border-radius:6px;font:inherit}button{cursor:pointer}button:hover{border-color:#84cec3}button:disabled{opacity:.4;cursor:default}
.lead{background:#182630;border:1px solid #354550;border-radius:10px;padding:18px;margin:14px 0}.lead h2{margin:0;font-size:1.1rem}.lead p{margin:10px 0}.address{padding:12px 0;border-bottom:1px solid #354550}.address code,.address small{display:block}
.folder-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}.folder-grid button{text-align:left;overflow-wrap:anywhere}.grid figcaption{overflow-wrap:anywhere}.media-button{width:100%;height:220px;display:flex;flex-direction:column;justify-content:center;align-items:center;border:none}.video-icon{font-size:3rem;color:#84cec3}
dialog{background:#101820;color:#e7edf2;border:1px solid #60727d;border-radius:12px;width:min(1100px,90vw);max-height:92vh}dialog::backdrop{background:#000b}#viewer-media img,#viewer-media video{display:block;width:100%;height:65vh;object-fit:contain}#viewer-caption{overflow-wrap:anywhere}
"""


def page(title, content, script="", *, css="", body_class=""):
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src \'self\' data:; '
            'media-src \'self\' data:; connect-src \'self\'; style-src \'unsafe-inline\'; script-src \'self\' \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
            f'<title>{esc(title)}</title><style>{STYLE}\n{css}</style></head><body class="{esc(body_class)}"><main>{content}</main>'
            f'<script>{script}</script></body></html>').encode()


def write_report(store):
    from .crypto import audit
    from .dashboard import write_dashboard
    audit(store, count=store.get("crypto_scope", {}).get("address_count",20))
    findings = clean(list(store.findings()))
    volumes = clean(store.volumes())
    stages = clean([dict(r) for r in store.db.execute("SELECT * FROM stages WHERE name NOT LIKE 'enrich:%' ORDER BY name")])
    image = clean(store.get("image", {}))
    layout = clean(store.get("layout", {}))
    file_count = store.db.execute("SELECT count(*) FROM files").fetchone()[0]
    exported = store.db.execute("SELECT count(*) FROM files WHERE artifact IS NOT NULL").fetchone()[0]
    analyses = clean([json.loads(row[0]) for row in store.db.execute("SELECT data FROM analyses ORDER BY id")])
    browser_history = write_browser_history(store)
    data = {"version": store.get("version"), "status": store.get("status", "initializing"), "image": image,
            "layout": layout, "volumes": volumes, "stages": stages, "findings": findings,
            "file_count": file_count, "exported_count": exported, "ai_analyses": analyses,
            "tools": store.get("tools", {}), "config": store.get("config", {}), "enrichment": store.get("enrichment", {}),
            "browser_history": browser_history}
    # Export all inventory rows; protect CSV consumers against formula injection.
    csv_out = io.StringIO()
    writer = csv.writer(csv_out)
    columns = ["id", "volume", "inode", "path", "size", "deleted", "category", "status", "artifact", "sha256", "detail"]
    writer.writerow(columns)
    for row in store.db.execute("SELECT * FROM files ORDER BY priority,id"):
        values = [str(row[key] or "") if key in ("sha256", "artifact") else redact(str(row[key] or "")) for key in columns]
        writer.writerow(["'" + v if v.startswith(("=", "+", "-", "@", "\t", "\r")) else v for v in values])
    atomic_write(store.root / "inventory.csv", csv_out.getvalue().encode())
    title = "Cold Digger · Evidence report"
    hash_status = image.get("sha256_status", "recorded" if image.get("sha256") else "pending")
    body = [f"<h1>{title}</h1><p class='muted'>Local analysis · {esc(data['status'])} · scanner {esc(data['version'])}</p>",
            f"<p><code>{esc(image.get('path',''))}</code><br>Source check: {esc(image.get('hash_mode','full' if image.get('sha256') else 'pending'))}"
            f"<br>Image SHA-256 ({esc(hash_status)}): <code>{esc(image.get('sha256') or 'Not computed')}</code></p>",
            "<div class='cards'>"]
    for label, count in (("Volumes", len(volumes)), ("File records", file_count), ("Exported candidates", exported), ("Findings", len(findings))):
        body.append(f"<div class='card'><strong>{count:,}</strong>{label}</div>")
    body += ["</div>", "<p><a href='findings.json'>Structured report</a> · <a href='inventory.csv'>Full file inventory</a> · <a href='media.html'>Private media gallery</a> · <a href='browser-history.html'>Browser history</a></p>",
             "<p class='notice'>Crypto hits are candidates, not proof of ownership or accessible funds. Raw/carved data has unknown deletion status unless filesystem metadata establishes it. Reports mask recognized key and seed patterns; all case files still contain private information.</p>",
             "<h2>Scan coverage</h2><div class='scroll'><table><tr><th>Stage</th><th>Status</th><th>Details</th></tr>"]
    for stage in stages:
        body.append(f"<tr><td>{esc(stage['name'])}</td><td>{esc(stage['status'])}</td><td>{esc(stage['detail'])}</td></tr>")
    body += ["</table></div><h2>Disk layout</h2>", f"<p>Partition scheme: {esc(layout.get('scheme','pending'))}; logical sector size: {esc(layout.get('sector_size','pending'))} bytes.</p>"]
    for warning in layout.get("warnings", []):
        body.append(f"<p class='notice'>{esc(warning)}</p>")
    body.append("<table><tr><th>Volume</th><th>Start byte</th><th>Length</th><th>Type / filesystem</th><th>Coverage</th></tr>")
    for volume in volumes:
        body.append(f"<tr><td>{esc(volume['id'])} {esc(volume.get('name',''))}</td><td>{volume['start']:,}</td><td>{volume['length']:,}</td><td>{esc(volume.get('filesystem',volume['signature']))}</td><td>{esc(volume['filesystem_status'])}</td></tr>")
    body.append("</table><details><summary>Regions outside discovered volumes</summary><pre>" + esc(json.dumps(layout.get("gaps", []), indent=2)) + "</pre></details>")
    body.append(f"<h2>Browser history</h2><p>{browser_history['records']:,} structured records from {browser_history['databases']} databases. <a href='browser-history.html'>Browse history, domains and source coverage</a>.</p>")
    body += ["<h2>Findings</h2><p>Findings are grouped by type and content fingerprint. Every retained source remains attached. Showing up to 2,000 groups; JSON contains all groups.</p>",
             "<input id='filter' aria-label='Filter findings' placeholder='Filter by type, path, volume or evidence ID'>",
             "<div class='scroll'><table id='findings'><thead><tr><th>Evidence</th><th>Finding</th><th>Assessment</th><th>Sources</th></tr></thead><tbody>"]
    for finding in findings[:2000]:
        body.append(f"<tr id='{esc(finding['id'])}'><td><code>{esc(finding['id'])}</code><br>{esc(finding['category'])}</td><td>{esc(finding['title'])}<br><small>{esc(finding['kind'])}</small></td><td>{esc(finding['confidence'])}<br>{esc(finding['validation'])}</td><td><details><summary>{len(finding['sources'])} occurrence(s)</summary><pre>{esc(json.dumps(finding['sources'][:100],indent=2))}</pre></details></td></tr>")
    body.append("</tbody></table></div><h2>Local AI analysis</h2>")
    if not analyses:
        body.append("<p>No AI analysis has been run. Recovery findings remain available independently.</p>")
    for analysis in analyses:
        body.append(f"<p>Model: {esc(analysis.get('model'))}. AI conclusions require review; evidence citations do not establish correctness.</p>")
        for claim in analysis.get("claims", []):
            links = " ".join(f"<a href='#{esc(ident)}'>{esc(ident)}</a>" for ident in claim["evidence_ids"])
            body.append(f"<p><strong>{esc(claim['title'])}</strong> ({esc(claim['type'])})<br>{esc(claim['explanation'])}<br>{links}</p>")
        body.append(f"<p class='muted'>{esc(analysis.get('scope',''))}</p>")
    duplicates = list(store.db.execute("SELECT sha256,count(*) n FROM files WHERE sha256 IS NOT NULL GROUP BY sha256 HAVING count(*)>1 ORDER BY n DESC LIMIT 100"))
    body.append("<h2>Duplicate content</h2><p>Identical exports at different source locations may indicate backups or copies. Their relationship is not established by the hash alone.</p>")
    for duplicate in duplicates:
        refs = [dict(r) for r in store.db.execute("SELECT id,volume,path FROM files WHERE sha256=?", (duplicate["sha256"],))]
        body.append(f"<details><summary>{duplicate['n']} identical exports · {esc(duplicate['sha256'][:16])}</summary><pre>{esc(json.dumps(clean(refs),indent=2))}</pre></details>")
    script = "document.getElementById('filter').addEventListener('input',function(){let q=this.value.toLowerCase();document.querySelectorAll('#findings tbody tr').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(q));});"
    atomic_write(store.root / "details.html", page(title, "<p><a href='report.html'>Recovery overview</a></p>" + "".join(body), script))
    write_dashboard(store, data)
    atomic_json(store.root / "findings.json", data)


def history_url(value):
    """Report URLs have no userinfo, query values, fragments or active links."""
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.hostname:
            return "[Non-web URL retained in private case database]"
        netloc = parts.netloc.rsplit("@", 1)[-1]
        return urlunsplit((parts.scheme, redact(netloc), redact(unquote(parts.path)),
                           "[query omitted]" if parts.query else "", "[fragment omitted]" if parts.fragment else ""))
    except ValueError:
        return "[Unparseable URL retained in private case database]"


def history_record(row):
    item = dict(row)
    item["url"] = history_url(item["url"])
    item["source"] = json.loads(item["source"])
    return clean(item)


def write_browser_history(store):
    sources = [clean({**dict(row), "detail": json.loads(row["detail"])}) for row in store.db.execute(
        "SELECT * FROM browser_sources WHERE status<>'not-browser' ORDER BY file_id")]
    count = store.db.execute("SELECT count(*) FROM browser_history").fetchone()[0]
    domains = [dict(row) for row in store.db.execute(
        "SELECT domain,count(*) records FROM browser_history WHERE domain<>'' GROUP BY domain ORDER BY records DESC,domain LIMIT 25")]
    summary = {"records": count, "databases": len(sources), "sources": sources,
               "top_domains": domains, "html": "browser-history.html", "csv": "browser-history.csv", "json": "browser-history.json"}
    columns = ["id", "file_id", "browser", "profile", "kind", "visited_utc", "visited_raw", "epoch", "url", "title",
               "domain", "visit_count", "transition", "origin"]
    json_path = store.root / "browser-history.json"
    csv_path = store.root / "browser-history.csv"
    json_temp, csv_temp = json_path.with_suffix(".json.tmp"), csv_path.with_suffix(".csv.tmp")
    json_fd = os.open(json_temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    csv_fd = os.open(csv_temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    previews = []
    with os.fdopen(json_fd, "w", encoding="utf-8") as out, os.fdopen(csv_fd, "w", encoding="utf-8", newline="") as csv_out:
        writer = csv.writer(csv_out)
        writer.writerow(columns)
        out.write('{"summary":' + json.dumps(summary, ensure_ascii=True) + ',"records":[')
        first = True
        for row in store.db.execute("SELECT * FROM browser_history ORDER BY visited_utc DESC,id"):
            item = history_record(row)
            out.write(("" if first else ",") + json.dumps(item, ensure_ascii=True))
            first = False
            values = [str(item[key]) if item[key] is not None else "" for key in columns]
            writer.writerow(["'" + v if v.startswith(("=", "+", "-", "@", "\t", "\r")) else v for v in values])
            if len(previews) < 2000:
                previews.append(item)
        out.write("]}")
    os.replace(json_temp, json_path)
    os.replace(csv_temp, csv_path)
    body = ["<h1>Browser history</h1><p><a href='report.html'>Main report</a> · <a href='browser-history.csv'>Full CSV</a> · <a href='browser-history.json'>Full JSON</a></p>",
            f"<p>{count:,} records from {len(sources)} recovered database sources. Up to 2,000 records are shown here, newest first.</p>",
            "<p class='notice'>These are browser database observations, potentially including sync/import activity. A visit does not prove a particular person's activity or account ownership. Copies of a database can repeat the same visits. URL summaries are not individual visits; visit_count is the URL's stored total.</p>",
            "<p>Times with a known UTC basis are converted to UTC; local IE weekly timestamps retain an unknown timezone. Raw timestamps and their epochs are in the exports. Cache references are not visits. IE rows may lack page titles. Titles describe stored URL metadata, not necessarily the title at the time of a visit. Queries, fragments and URL credentials are omitted here. Full originals remain in private case files. Links are displayed as text and never fetched.</p>",
            "<h2>Source coverage</h2><table><tr><th>Evidence file</th><th>Original path</th><th>Status / scope</th></tr>"]
    for source in sources:
        body.append(f"<tr><td><code>{esc(source['file_id'])}</code></td><td>{esc(source['path'])}</td><td>{esc(source['status'])}<details><summary>Details</summary><pre>{esc(json.dumps(source['detail'],indent=2))}</pre></details></td></tr>")
    body.append("</table><h2>Most represented domains</h2><p>Counts describe extracted records, including duplicates across database copies.</p><table><tr><th>Domain</th><th>Records</th></tr>")
    for item in domains:
        body.append(f"<tr><td>{esc(item['domain'])}</td><td>{item['records']}</td></tr>")
    body.append("</table><h2>Recorded history</h2><input id='filter' aria-label='Filter browser history' placeholder='Filter by domain, title, browser, profile or evidence ID'><div class='scroll'><table id='history'><thead><tr><th>UTC time / kind</th><th>Page</th><th>Browser / profile</th><th>Evidence</th></tr></thead><tbody>")
    for item in previews:
        when = item['visited_utc'] or ('Local time; timezone unknown' if item['kind'].endswith('local-time') else 'No UTC visit time established')
        body.append(f"<tr id='{esc(item['id'])}'><td>{esc(when)}<br>{esc(item['kind'])}</td><td>{esc(item['title'])}<br><code>{esc(item['url'])}</code></td><td>{esc(item['browser'])}<br>{esc(item['profile'])}</td><td><code>{esc(item['id'])}</code><details><summary>{esc(item['file_id'])}</summary><pre>{esc(json.dumps(item['source'],indent=2))}</pre></details></td></tr>")
    body.append("</tbody></table></div>")
    script = "document.getElementById('filter').addEventListener('input',function(){let q=this.value.toLowerCase();document.querySelectorAll('#history tbody tr').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(q));});"
    atomic_write(store.root / "browser-history.html", page("Cold Digger · Browser history", "".join(body), script))
    return summary
