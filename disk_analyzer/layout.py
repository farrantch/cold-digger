"""Bounded, read-only MBR/EBR and GPT discovery. All stored ranges are bytes."""
from __future__ import annotations

from pathlib import Path
import struct
import uuid
import zlib


def signature(data: bytes) -> str:
    if data.startswith(b"LUKS\xba\xbe"):
        return "luks-encrypted"
    if data[3:11] == b"-FVE-FS-":
        return "bitlocker-encrypted"
    if b"LABELONE" in data[:2048] and b"LVM2" in data[:2048]:
        return "lvm-container"
    if data[3:11] == b"NTFS    ":
        return "ntfs"
    if data[3:11] == b"EXFAT   ":
        return "exfat"
    if data[54:62].startswith(b"FAT") or data[82:90].startswith(b"FAT"):
        return "fat"
    if data[1080:1082] == b"\x53\xef":
        return "ext"
    if data[:4] == b"XFSB":
        return "xfs"
    if data[32:36] == b"NXSB":
        return "apfs-container"
    return "unknown"


def discover(path: Path, sector_size: int | None = None) -> dict:
    size = path.stat().st_size
    warnings = []
    volumes = []
    metadata = []
    with path.open("rb") as stream:
        def read(offset, length):
            if offset < 0 or offset + length > size:
                return b""
            stream.seek(offset)
            return stream.read(length)

        def gpt_header(offset, ss):
            raw = read(offset, ss)
            if raw[:8] != b"EFI PART" or len(raw) < 92:
                return None
            length = struct.unpack_from("<I", raw, 12)[0]
            if not 92 <= length <= ss:
                return None
            header = bytearray(raw[:length])
            checksum = struct.unpack_from("<I", header, 16)[0]
            header[16:20] = b"\0" * 4
            if zlib.crc32(header) != checksum:
                return None
            current, backup, first, last = struct.unpack_from("<QQQQ", raw, 24)
            entries, count, entry_size, entries_crc = struct.unpack_from("<QIII", raw, 72)
            if current * ss != offset or backup * ss >= size or first > last or last * ss >= size:
                return None
            if not 128 <= entry_size <= 4096 or not 1 <= count <= 16384 or count * entry_size > 16 * 1024**2:
                return None
            table = read(entries * ss, count * entry_size)
            if len(table) != count * entry_size or zlib.crc32(table) != entries_crc:
                return None
            return raw, table, count, entry_size, first, last, entries, backup

        candidates = [sector_size] if sector_size else [512, 4096]
        chosen = None
        for ss in candidates:
            for offset in (ss, size - ss):
                header = gpt_header(offset, ss)
                if header:
                    chosen = ss, offset, header
                    break
            if chosen:
                break
        ss = chosen[0] if chosen else (sector_size or 512)
        if not chosen and sector_size is None:
            warnings.append("Logical sector size assumed to be 512 bytes; raw images do not record it. Use --sector-size if known.")

        def add(ident, start, length, kind, name=""):
            if start < 0 or length <= 0 or start + length > size:
                warnings.append(f"Rejected out-of-bounds partition {ident}.")
                return
            volumes.append({"id": ident, "start": start, "length": length,
                            "type": kind, "name": name,
                            "signature": signature(read(start, min(length, 4096))),
                            "filesystem_status": "pending"})

        if chosen:
            scheme = "gpt"
            _, offset, (header, table, count, entry_size, first, last, entries, backup) = chosen
            if offset != ss:
                warnings.append("Primary GPT invalid or absent; using validated backup GPT.")
            metadata = [(0, first * ss), ((last + 1) * ss, size)]
            for index in range(count):
                entry = table[index * entry_size:(index + 1) * entry_size]
                if entry[:16] == b"\0" * 16:
                    continue
                start, end = struct.unpack_from("<QQ", entry, 32)
                if start < first or end > last or start > end:
                    warnings.append(f"Rejected invalid GPT entry {index + 1}.")
                    continue
                add(f"p{index + 1}", start * ss, (end - start + 1) * ss,
                    str(uuid.UUID(bytes_le=entry[:16])), entry[56:128].decode("utf-16le", "replace").rstrip("\0"))
        else:
            mbr = read(0, 512)
            scheme = "none"
            extended = []
            if len(mbr) == 512 and mbr[510:512] == b"\x55\xaa":
                for i in range(4):
                    entry = mbr[446 + i * 16:462 + i * 16]
                    kind = entry[4]
                    start, length = struct.unpack_from("<II", entry, 8)
                    if not kind or not length:
                        continue
                    if kind == 0xEE:
                        warnings.append("Protective MBR found but neither GPT copy validated; partition coverage is incomplete.")
                        continue
                    if entry[0] not in (0, 0x80) or start == 0:
                        continue
                    scheme = "mbr"
                    if kind in (0x05, 0x0F, 0x85):
                        extended.append((start, length))
                    else:
                        add(f"p{i + 1}", start * ss, length * ss, f"mbr-{kind:02x}")
                metadata = [(0, ss)]
            logical = 5
            for base, container_length in extended:
                current = base
                visited = set()
                for _ in range(1024):
                    if current in visited:
                        warnings.append("Cyclic EBR chain detected; stopped following it.")
                        break
                    visited.add(current)
                    if not base <= current < base + container_length:
                        warnings.append("EBR outside its extended partition; stopped.")
                        break
                    ebr = read(current * ss, 512)
                    if len(ebr) != 512 or ebr[510:] != b"\x55\xaa":
                        warnings.append("Invalid EBR; logical partition discovery is incomplete.")
                        break
                    metadata.append((current * ss, (current + 1) * ss))
                    rel, length = struct.unpack_from("<II", ebr, 454)
                    if rel and length and current + rel + length <= base + container_length:
                        add(f"p{logical}", (current + rel) * ss, length * ss, f"mbr-{ebr[450]:02x}")
                        logical += 1
                    next_rel = struct.unpack_from("<I", ebr, 470)[0]
                    if ebr[466] not in (0x05, 0x0F, 0x85) or not next_rel:
                        break
                    current = base + next_rel
                else:
                    warnings.append("EBR traversal limit reached.")

        if not volumes:
            add("whole", 0, size, "filesystem-probe")
            warnings.append("No usable partition entries. Probe the image as a filesystem; raw scanning remains available.")
        ordered = sorted(volumes, key=lambda v: v["start"])
        for previous, current in zip(ordered, ordered[1:]):
            if previous["start"] + previous["length"] > current["start"]:
                warnings.append(f"Overlapping volumes: {previous['id']} and {current['id']}.")
        occupied = sorted(metadata + [(v["start"], v["start"] + v["length"]) for v in volumes])
        gaps = []
        cursor = 0
        for start, end in occupied:
            if start > cursor:
                gaps.append({"start": cursor, "length": start - cursor})
            cursor = max(cursor, end)
        if cursor < size:
            gaps.append({"start": cursor, "length": size - cursor})
        return {"scheme": scheme, "sector_size": ss, "size": size,
                "volumes": volumes, "gaps": gaps, "warnings": warnings}


def locate(volumes, offset):
    return [v["id"] for v in volumes if v["start"] <= offset < v["start"] + v["length"]]
