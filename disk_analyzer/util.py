from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def digest_file(path: Path, progress=None) -> str:
    result = hashlib.sha256()
    done = 0
    last = time.monotonic()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            result.update(chunk)
            done += len(chunk)
            if progress and time.monotonic() - last > 10:
                progress(done)
                last = time.monotonic()
    return result.hexdigest()


def atomic_json(path: Path, value) -> None:
    atomic_write(path, json.dumps(value, indent=2, ensure_ascii=True).encode())


def atomic_write(path: Path, data: bytes) -> None:
    temp = path.with_name(path.name + ".tmp")
    # Case directories must be trusted, owned by the operator, and private.
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


@contextlib.contextmanager
def case_lock(path: Path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("Case directory must not be a symbolic link")
    os.chmod(path, 0o700)
    fd = os.open(path / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("Another process is using this case") from exc
        yield


def parse_size(value: str) -> int:
    suffixes = {"kib": 1024, "mib": 1024**2, "gib": 1024**3,
                "kb": 1000, "mb": 1000**2, "gb": 1000**3}
    text = value.strip().lower()
    for suffix, multiplier in suffixes.items():
        if text.endswith(suffix):
            result = int(float(text[:-len(suffix)]) * multiplier)
            break
    else:
        result = int(text)
    if result <= 0:
        raise ValueError("Size must be positive")
    return result


def archive_case(path: Path) -> Path:
    """Move a previous case aside while the caller holds case_lock(path).

    Keep the directory and its lock inode in place throughout restart, so every
    CLI process attempting to use the original path contends on the same lock.
    """
    database = path / "case.sqlite"
    if not database.is_file() or database.is_symlink():
        raise ValueError("Cannot restart: output is not an existing case directory")
    entries = [entry for entry in path.iterdir() if entry.name != ".lock"]
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup = Path(tempfile.mkdtemp(prefix=f"{path.name}.backup-{stamp}-", dir=path.parent))
    moved = []
    try:
        for entry in entries:
            target = backup / entry.name
            entry.rename(target)
            moved.append(target)
    except BaseException:
        try:
            for target in reversed(moved):
                target.rename(path / target.name)
            backup.rmdir()
        except OSError as exc:
            raise OSError(f"Restart archive interrupted; original data remains split between {path} and {backup}. "
                          "Restore it before resuming.") from exc
        raise
    return backup
