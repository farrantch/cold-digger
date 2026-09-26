from pathlib import Path
import struct
import tempfile
import unittest
import uuid
import zlib

from disk_analyzer.layout import discover


def gpt_image(path, ss=512):
    sectors = 1024
    raw = bytearray(ss * sectors)
    table = bytearray(128 * 128)
    for i, (start, end) in enumerate(((64, 255), (300, 500))):
        offset = i * 128
        table[offset:offset + 16] = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le
        table[offset + 16:offset + 32] = uuid.uuid4().bytes_le
        struct.pack_into("<QQ", table, offset + 32, start, end)
        name = f"volume{i+1}".encode("utf-16le")
        table[offset + 56:offset + 56 + len(name)] = name
    table_sectors = len(table) // ss
    raw[2 * ss:2 * ss + len(table)] = table
    backup_table = sectors - 1 - table_sectors
    raw[backup_table * ss:backup_table * ss + len(table)] = table
    for current, backup, entries in ((1, sectors - 1, 2), (sectors - 1, 1, backup_table)):
        header = bytearray(ss)
        header[:8] = b"EFI PART"
        struct.pack_into("<IIII", header, 8, 0x10000, 92, 0, 0)
        struct.pack_into("<QQQQ", header, 24, current, backup, 34, sectors - 34)
        struct.pack_into("<QIII", header, 72, entries, 128, 128, zlib.crc32(table))
        struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
        raw[current * ss:(current + 1) * ss] = header
    raw[510:512] = b"\x55\xaa"
    raw[450] = 0xee
    struct.pack_into("<II", raw, 454, 1, sectors - 1)
    path.write_bytes(raw)


class LayoutTests(unittest.TestCase):
    def test_gpt_sector_detection_and_backup(self):
        for ss in (512, 4096):
            with self.subTest(ss=ss), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "disk"
                gpt_image(path, ss)
                layout = discover(path)
                self.assertEqual(layout["sector_size"], ss)
                self.assertEqual(len(layout["volumes"]), 2)
                self.assertEqual(layout["volumes"][1]["start"], 300 * ss)
                with path.open("r+b") as stream:
                    stream.seek(ss + 16)
                    stream.write(b"\0" * 4)
                layout = discover(path)
                self.assertEqual(layout["scheme"], "gpt")
                self.assertTrue(any("backup" in warning for warning in layout["warnings"]))

    def test_mbr_and_logical_partition(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "disk"
            raw = bytearray(512 * 100)
            raw[510:512] = b"\x55\xaa"
            raw[450] = 0x83
            struct.pack_into("<II", raw, 454, 2, 10)
            raw[466] = 0x0f
            struct.pack_into("<II", raw, 470, 20, 60)
            ebr = 20 * 512
            raw[ebr + 510:ebr + 512] = b"\x55\xaa"
            raw[ebr + 450] = 0x83
            struct.pack_into("<II", raw, ebr + 454, 1, 10)
            path.write_bytes(raw)
            layout = discover(path)
            self.assertEqual([v["id"] for v in layout["volumes"]], ["p1", "p5"])
            self.assertEqual(layout["volumes"][1]["start"], 21 * 512)
            self.assertTrue(layout["gaps"])

    def test_invalid_bounds_and_unpartitioned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "disk"
            raw = bytearray(4096)
            raw[510:512] = b"\x55\xaa"
            raw[450] = 0x83
            struct.pack_into("<II", raw, 454, 100, 100)
            path.write_bytes(raw)
            layout = discover(path)
            self.assertEqual(layout["volumes"][0]["id"], "whole")
            self.assertTrue(any("out-of-bounds" in warning for warning in layout["warnings"]))
