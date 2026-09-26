"""Quick source metadata checks and optional full SHA-256 verification."""
from __future__ import annotations

from .util import digest_file, log


def stat_identity(stat):
    return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "ctime_ns": stat.st_ctime_ns,
            "inode": stat.st_ino, "device": stat.st_dev}


def metadata_matches(previous, current):
    # Older cases saved only size and mtime. Compare additional fields when
    # present, then retain the richer identity for subsequent quick resumes.
    return (all(key in previous for key in ("size", "mtime_ns")) and
            all(previous[key] == value for key, value in current.items() if key in previous))


def verify_image(image, before, previous, mode):
    current = stat_identity(before)
    previous = previous or {}
    digest = previous.get("sha256")
    if previous and (mode == "quick" or not digest) and not metadata_matches(previous, current):
        raise ValueError("Image metadata changed; refusing to reuse this case's checkpoints. "
                         "Use --hash-mode full if the case has a saved SHA-256, otherwise use a new case.")
    if mode == "full":
        log("Hashing source image for full SHA-256 verification")
        calculated = digest_file(image, lambda n: log(f"Image identity: {n:,}/{before.st_size:,} bytes hashed"))
        if digest and calculated != digest:
            raise ValueError("Image contents changed; refusing to resume this case")
        hash_status = "verified" if digest else "computed"
        digest = calculated
    else:
        log("Quick source identity check; skipping full-image hashing")
        hash_status = "previously-recorded" if digest else "not-computed"
    if stat_identity(image.stat()) != current:
        raise ValueError("Source changed during identity verification; refusing to start analysis")
    return dict(current, path=str(image), sha256=digest, hash_mode=mode, sha256_status=hash_status)
