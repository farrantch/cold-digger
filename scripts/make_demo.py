#!/usr/bin/env python3
"""Create a synthetic MBR disk with two ext2 volumes and public test secrets.

Requires e2fsprogs. Never use these keys or phrases for real funds.
"""
from pathlib import Path
import argparse
import hashlib
import os
import struct
import subprocess
import sqlite3
import zlib

SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def base58(payload):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 58)
        out = alphabet[remainder] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


WIF = base58(b"\x80" + (1).to_bytes(32, "big") + b"\x01")


def png():
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    pixels = b"".join(b"\0" + bytes((i * 37 + y * 11) % 256 for i in range(128 * 3)) for y in range(128))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 128, 128, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b"")


def make_demo(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    image = directory / "demo.img"
    if image.exists():
        raise ValueError("Demo image already exists; choose a new directory")
    materials = {"wallet-notes.txt": f"PUBLIC TEST DATA ONLY\nSeed phrase: {SEED}\n",
                 "deleted-key.txt": f"PUBLIC TEST DATA ONLY\nPrivate key: {WIF}\n",
                 "backup-notes.txt": "This computer had an Electrum wallet backup and a personal code project.\n"}
    for name, text in materials.items():
        (directory / name).write_text(text)
    (directory / "photo.png").write_bytes(png())
    (directory / "forgotten.payload").write_bytes(b"\0" * (3 * 1024**2) + b"Deleted unknown file type\n")
    with sqlite3.connect(directory / "History") as db:
        db.executescript("""
            CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INTEGER,last_visit_time INTEGER);
            CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER,transition INTEGER);
            INSERT INTO urls VALUES(1,'https://electrum.org/download','Electrum download',2,13348638245123456);
            INSERT INTO visits VALUES(1,1,13348638245123456,1);
            INSERT INTO visits VALUES(2,1,13348638246123456,0);
            CREATE TABLE padding(data BLOB);
        """)
        # Deliberately exceed the generic 2 MiB export threshold: extensionless
        # browser databases must still be recovered for structured inspection.
        db.execute("INSERT INTO padding VALUES(zeroblob(?))", (3 * 1024**2,))
    with sqlite3.connect(directory / "places.sqlite") as db:
        db.executescript("""
            CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INTEGER,last_visit_date INTEGER);
            CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY,place_id INTEGER,visit_date INTEGER,visit_type INTEGER);
            INSERT INTO moz_places VALUES(1,'https://example.org/photography','Photography notes',1,1704164645123456);
            INSERT INTO moz_historyvisits VALUES(1,1,1704164645123456,1);
        """)
    partitions = []
    for index, start in enumerate((2048, 20480), 1):
        part = directory / f"partition{index}.raw"
        with part.open("wb") as stream:
            stream.truncate(8 * 1024**2)
        subprocess.run(["mkfs.ext2", "-F", "-q", "-L", f"DEMO{index}", str(part)], check=True)
        names = ("wallet-notes.txt", "deleted-key.txt", "photo.png", "History") if index == 1 else ("backup-notes.txt", "photo.png", "places.sqlite", "forgotten.payload")
        for name in names:
            # debugfs has its own command parser; quote the controlled fixture path.
            source = str((directory / name).resolve())
            if '"' in source or '\n' in source:
                raise ValueError("Fixture directory cannot contain quotes/newlines")
            subprocess.run(["debugfs", "-w", "-R", f'write "{source}" /{name}', str(part)],
                           check=True, capture_output=True)
        if index == 1:
            subprocess.run(["debugfs", "-w", "-R", "rm /deleted-key.txt", str(part)], check=True, capture_output=True)
        else:
            for name in ("places.sqlite", "forgotten.payload"):
                subprocess.run(["debugfs", "-w", "-R", f"rm /{name}", str(part)], check=True, capture_output=True)
        partitions.append((start, part))
    mbr = bytearray(512)
    for index, (start, part) in enumerate(partitions):
        struct.pack_into("<B3sB3sII", mbr, 446 + index * 16, 0, b"\0" * 3, 0x83, b"\0" * 3,
                         start, part.stat().st_size // 512)
    mbr[510:] = b"\x55\xaa"
    with image.open("wb") as stream:
        stream.truncate(20 * 1024**2)
        stream.write(mbr)
        for start, part in partitions:
            stream.seek(start * 512)
            stream.write(part.read_bytes())
        # A public test key in a gap, independent of either filesystem.
        stream.seek(19 * 1024**2)
        stream.write(b"PUBLIC TEST DATA ONLY\n" + WIF.encode() + b"\n")
    return image


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(make_demo(args.directory))
