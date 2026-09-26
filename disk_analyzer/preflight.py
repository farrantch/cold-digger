"""Reject missing recovery dependencies before reading image contents."""
from __future__ import annotations

from .process import doctor
from .util import log


def check_dependencies(config, *, allow_partial=False):
    tools = doctor()
    required = {
        "fsstat": ("sleuthkit", "filesystem detection"),
        "fls": ("sleuthkit", "allocated and deleted file inventory"),
        "icat": ("sleuthkit", "allocated and deleted file recovery"),
        "pymsiecf": ("python3-libmsiecf", "Internet Explorer index.dat history"),
        "pyesedb": ("python3-libesedb", "Internet Explorer WebCache history"),
    }
    if config["carve"] != "off":
        required["photorec"] = ("testdisk", "signature carving, including deleted content")
    if config["ocr"]:
        required["tesseract"] = ("tesseract-ocr", "requested OCR")
    if config["bulk"]:
        required["bulk_extractor"] = ("bulk_extractor", "requested bulk extraction")
    missing = {name: detail for name, detail in required.items()
               if not tools.get(name, {}).get("available")}
    if not tools.get("bip_utils",{}).get("available"):
        missing["bip_utils"] = ("python-project", "automatic key validation and address derivation")
    if missing:
        packages = sorted({package for package, _ in missing.values() if package not in ("bulk_extractor","python-project")})
        lines = ["Missing required recovery tools:"]
        lines.extend(f"  {name}: {purpose}" for name, (_, purpose) in missing.items())
        if packages:
            lines.append("Install on Ubuntu: sudo apt install " + " ".join(packages))
        if "bulk_extractor" in missing:
            lines.append("Install bulk_extractor separately or omit --bulk (use --no-bulk on resume).")
        if "bip_utils" in missing:
            lines.append("Install project dependencies in a Python 3.11–3.13 environment: python -m pip install -e .")
        if not allow_partial:
            lines.append("Stopped before hashing or scanning the image. Existing case results are preserved.")
            lines.append("Use --allow-partial only to deliberately accept missing recovery coverage for this run.")
            raise ValueError("\n".join(lines))
        log("WARNING: --allow-partial requested; recovery coverage will be incomplete.\n" + "\n".join(lines))
    else:
        log("Recovery tools ready: filesystem/deleted files and browser history" +
            (", plus PhotoRec carving" if config["carve"] != "off" else "; carving disabled"))
    return tools
