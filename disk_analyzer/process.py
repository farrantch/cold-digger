"""External tools run without a shell, with time and output limits."""
from __future__ import annotations

import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import time


def available(name):
    return shutil.which(name)


def terminate(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    except ProcessLookupError:
        pass


def run_file(argv, output: Path, error: Path, *, timeout=300, max_bytes=256 * 1024**2,
             cwd=None, monitor=None):
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_bytes, max_bytes))

    env = dict(os.environ, LC_ALL="C", TZ="UTC", TERM="dumb")
    with output.open("wb") as out, error.open("wb") as err:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                   cwd=cwd, env=env, start_new_session=True, preexec_fn=limits)
        start = time.monotonic()
        reason = ""
        try:
            while process.poll() is None:
                if timeout and time.monotonic() - start > timeout:
                    reason = "tool timeout"
                    terminate(process)
                    break
                if monitor:
                    reason = monitor() or ""
                    if reason:
                        terminate(process)
                        break
                time.sleep(0.1)
        except BaseException:
            terminate(process)
            raise
    if output.stat().st_size >= max_bytes and process.returncode:
        reason = reason or "tool output limit reached"
    return process.returncode, reason


def doctor():
    from .ie import reader
    from .crypto import backend
    result = {}
    for name in ("mmls", "fsstat", "fls", "icat", "photorec", "bulk_extractor", "pdftotext", "tesseract", "ffprobe", "ffmpeg"):
        executable = available(name)
        detail = {"available": bool(executable), "path": executable}
        if executable:
            flag = "-V" if name in ("mmls", "fsstat", "fls", "icat", "bulk_extractor") else (
                "/version" if name == "photorec" else "--version" if name == "tesseract" else "-version" if name in ("ffprobe", "ffmpeg") else "-v")
            try:
                out = subprocess.run([executable, flag], capture_output=True, timeout=5, check=False)
                detail["version"] = (out.stdout + out.stderr).decode("utf-8", "replace")[:500].strip()
            except (OSError, subprocess.TimeoutExpired):
                detail["version"] = "version query failed"
        result[name] = detail
    try:
        import PIL
        result["pillow"] = {"available": True, "version": PIL.__version__}
    except ImportError:
        result["pillow"] = {"available": False}
    for family in ("ie-index", "ie-webcache"):
        detail = reader(family)
        result[detail["module"]] = detail
    result["bip_utils"] = backend()
    return result
