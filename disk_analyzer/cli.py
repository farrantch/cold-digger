from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import urllib.error

from . import __version__
from .ai import analyze
from .browser import extract_history
from .crypto import audit
from .balances import check_balances
from .content import prepare_media
from .identity import verify_image
from .pipeline import DEFAULTS, completion_status, scan, validate_config
from .preflight import check_dependencies
from .process import doctor
from .report import write_report
from .store import Store
from .util import archive_case, case_lock, log, parse_size


def parser():
    root = argparse.ArgumentParser(prog="cold-digger", description="Local, read-only raw disk-image analysis")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Show installed forensic tools; does not install anything")
    p = commands.add_parser("serve", help="Browse a case locally and open individual files from its image on demand")
    p.add_argument("case", type=Path)
    source = p.add_mutually_exclusive_group()
    source.add_argument("--image", type=Path, help="Source image; defaults to the path saved in the case")
    source.add_argument("--exports-only", action="store_true", help="Browse exports without access to the source image")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--max-file-bytes", type=parse_size, default=4 * 1024**3)
    p.add_argument("--cache-bytes", type=parse_size, default=8 * 1024**3)
    p.add_argument("--read-timeout", type=int, default=900)
    p = commands.add_parser("scan", help="Analyze a raw whole-disk or partition image")
    p.add_argument("image", type=Path)
    p.add_argument("--output", "-o", type=Path, required=True)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--resume", action="store_true", help="Continue an existing case using its saved settings/checkpoints")
    mode.add_argument("--restart", action="store_true", help="Archive the existing case and start fresh at the same output path")
    p.add_argument("--allow-partial", action="store_true",
                   help="Explicitly allow missing recovery tools for this run (default: stop before scanning)")
    p.add_argument("--hash-mode", choices=("quick", "full"),
                   help="Source identity check: quick metadata check (default for new cases), or full SHA-256")
    p.add_argument("--sector-size", type=int, choices=(512, 4096))
    p.add_argument("--chunk-size", type=parse_size)
    p.add_argument("--max-file-bytes", type=parse_size, help="Per-file recovery limit (default 4 GiB)")
    p.add_argument("--max-output-bytes", type=parse_size)
    p.add_argument("--max-files", type=int, help="Optional records per volume; 0 means unlimited (default, including resume)")
    p.add_argument("--max-browser-rows", type=int, help="History records per database (default 100000)")
    p.add_argument("--tool-timeout", type=int, help="Per long-running tool timeout in seconds (default 86400)")
    p.add_argument("--carve", choices=("auto", "on", "off"))
    p.add_argument("--bulk", action=argparse.BooleanOptionalAction, default=None)
    p.add_argument("--ocr", action=argparse.BooleanOptionalAction, default=None)
    for command in ("report", "status", "analyze", "history", "validate", "media", "balances"):
        p = commands.add_parser(command)
        p.add_argument("case", type=Path)
        if command == "balances":
            p.add_argument("--allow-network", action="store_true")
            p.add_argument("--bitcoin-api", help="Bitcoin mainnet Esplora API URL (public addresses only)")
            p.add_argument("--ethereum-rpc", help="Ethereum mainnet JSON-RPC URL (native ETH only)")
            p.add_argument("--include-background", action="store_true", help="Also check low-priority/example candidates")
        if command == "validate":
            p.add_argument("--image", type=Path, help="Optional original image for bounded reads of legacy raw candidates/context")
            p.add_argument("--address-count", type=int, default=20, help="Address indices per supported derivation branch")
        if command == "history":
            p.add_argument("--max-rows", type=int, default=100000)
        if command == "analyze":
            p.add_argument("--model", required=True)
            p.add_argument("--url", default="http://127.0.0.1:11434")
            p.add_argument("--max-findings", type=int, default=100)
    return root


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    try:
        if args.command == "doctor":
            print(json.dumps(doctor(), indent=2))
            return 0
        if args.command == "scan":
            image = args.image.resolve(strict=True)
            if not image.is_file() or image.stat().st_size == 0:
                raise ValueError("Input must be a nonempty regular raw image file")
            output = args.output.absolute()
            if output.is_symlink():
                raise ValueError("Output directory must not be a symlink")
            output = output.resolve()
            if output == image or output in image.parents:
                raise ValueError("Input image must live outside the output case directory")
            if output.exists() and not (output / "case.sqlite").exists() and any(p.name != ".lock" for p in output.iterdir()):
                raise ValueError("New case output must be empty to avoid overwriting existing files")
            overrides = {key: value for key, value in vars(args).items()
                         if key not in ("command", "image", "output", "resume", "restart", "allow_partial") and value is not None}
            if args.restart:
                # Reject bad input/settings before moving the existing case.
                validate_config({**DEFAULTS, **overrides})
                if not (output / "case.sqlite").is_file():
                    raise ValueError("Cannot restart: output is not an existing case directory")
            with case_lock(output):
                tool_report = None
                if args.restart:
                    tool_report = check_dependencies({**DEFAULTS, **overrides}, allow_partial=args.allow_partial)
                    backup = archive_case(output)
                    log(f"Previous case archived at {backup}; starting a fresh scan")
                return scan(image, output, overrides, args.resume,
                            allow_partial=args.allow_partial, tool_report=tool_report)
        case = args.case.resolve(strict=True)
        if not (case / "case.sqlite").is_file():
            raise ValueError("Not a cold-digger case directory")
        if args.command == "serve":
            from .serve import BrowseService, CaseServer
            if not 0 <= args.port <= 65535:
                raise ValueError("Port must be between 0 and 65535")
            with case_lock(case):
                store = Store(case)
                try:
                    source = None if args.exports_only else args.image or store.get("image", {}).get("path")
                    if not args.exports_only and not source:
                        raise ValueError("Supply --image or use --exports-only")
                    service = BrowseService(case, source, max_file_bytes=args.max_file_bytes,
                                            cache_bytes=args.cache_bytes, timeout=args.read_timeout)
                    try:
                        write_report(store)
                    except BaseException:
                        service.close()
                        raise
                finally:
                    store.close()
            # Browsing uses independent read-only DB connections. It does not hold
            # the scan lock or change recovery statuses/stages.
            try:
                with CaseServer(service, args.port) as server:
                    log(f"Local browser: {server.url}media.html")
                    log("On-demand file cache is temporary. Ctrl-C stops the browser and clears the cache.")
                    try:
                        server.serve_forever(poll_interval=.25)
                    except KeyboardInterrupt:
                        service.stopping.set()
            finally:
                service.close()
            return 0
        with case_lock(case):
            store = Store(case)
            try:
                if args.command == "status":
                    print(json.dumps({"status": store.get("status"), "stages": [dict(r) for r in store.db.execute(
                        "SELECT * FROM stages WHERE name NOT LIKE 'enrich:%'")]}, indent=2))
                elif args.command == "report":
                    write_report(store)
                    log(str(case / "report.html"))
                elif args.command == "validate":
                    image = args.image.resolve(strict=True) if args.image else None
                    if image:
                        verify_image(image,image.stat(),store.get("image"),"quick")
                    audit(store,image,args.address_count)
                    write_report(store)
                    log(str(case / "crypto.html"))
                elif args.command == "media":
                    result = prepare_media(store)
                    write_report(store)
                    log(str(case / "media.html"))
                    return result
                elif args.command == "balances":
                    result = check_balances(store,bitcoin_api=args.bitcoin_api,ethereum_rpc=args.ethereum_rpc,
                                            allow_network=args.allow_network,include_background=args.include_background)
                    write_report(store)
                    log(str(case / "crypto.html"))
                    return result
                elif args.command == "history":
                    result = extract_history(store, args.max_rows)
                    if store.get("status") in ("complete", "complete-with-gaps"):
                        store.put("status", completion_status(store))
                    write_report(store)
                    log(str(case / "browser-history.html"))
                    return result
                else:
                    if not 1 <= args.max_findings <= 1000:
                        raise ValueError("--max-findings must be between 1 and 1000")
                    count = analyze(store, args.model, args.url, args.max_findings)
                    log(f"Saved {count} AI suggestions to {case / 'report.html'}")
            finally:
                store.close()
        return 0
    except KeyboardInterrupt:
        print("cold-digger: Interrupted before scanning", file=sys.stderr)
        return 130
    except (ValueError, OSError, urllib.error.URLError) as exc:
        print(f"cold-digger: {exc}", file=sys.stderr)
        return 1
