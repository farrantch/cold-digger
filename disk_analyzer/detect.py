"""Deterministic candidate detection. Structural validity is not wallet ownership."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
from importlib.resources import files
import json
import re

WORDS = files("disk_analyzer").joinpath("data/bip39-english.txt").read_text().splitlines()
WORD_INDEX = {word: index for index, word in enumerate(WORDS)}
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
EXT_PRIVATE = {0x0488ADE4, 0x04358394, 0x049D7878, 0x04B2430C, 0x044A4E28, 0x045F18BC}
EXT_PUBLIC = {0x0488B21E, 0x043587CF, 0x049D7CB2, 0x04B24746, 0x044A5262, 0x045F1CF6}
OVERLAP = 8192
MATERIAL_KINDS = {"bitcoin_address", "ethereum_address", "extended_public_key"}


@dataclass
class Hit:
    kind: str
    title: str
    value: bytes
    start: int
    end: int
    confidence: str = "lead"
    validation: str = "Pattern only; requires review"
    category: str = "crypto"
    secret: bool = False


def base58check(text):
    value = 0
    try:
        for char in text:
            value = value * 58 + B58.index(char)
    except ValueError:
        return None
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(text) - len(text.lstrip("1"))) + raw
    if len(raw) < 5 or hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        return None
    return raw[:-4]


def valid_mnemonic(words):
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    value = 0
    try:
        for word in words:
            value = (value << 11) | WORD_INDEX[word]
    except KeyError:
        return False
    checksum_bits = len(words) // 3
    entropy_bits = len(words) * 11 - checksum_bits
    entropy = (value >> checksum_bits).to_bytes(entropy_bits // 8, "big")
    return value & ((1 << checksum_bits) - 1) == hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)


def valid_bech32(address):
    if address.lower() != address and address.upper() != address:
        return False
    address = address.lower()
    hrp, _, encoded = address.rpartition("1")
    if hrp not in ("bc", "tb", "bcrt") or not 7 <= len(encoded) <= 87:
        return False
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    try:
        data = [alphabet.index(c) for c in encoded]
    except ValueError:
        return False
    checksum = 1
    for value in [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data:
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ value
        for i, generator in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if (top >> i) & 1:
                checksum ^= generator
    version = data[0]
    if version > 16 or checksum != (1 if version == 0 else 0x2bc830a3):
        return False
    acc = bits = 0
    program = []
    for value in data[1:-6]:
        acc = (acc << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            program.append((acc >> bits) & 255)
    if bits >= 5 or ((acc << (8 - bits)) & 255):
        return False
    return 2 <= len(program) <= 40 and (version != 0 or len(program) in (20, 32))


BASE58_PATTERN = re.compile(r"(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{26,112}(?![A-Za-z0-9])")
BECH32_PATTERN = re.compile(r"(?<![A-Za-z0-9])(?:bc1|tb1|bcrt1)[a-zA-Z0-9]{8,87}(?![A-Za-z0-9])", re.I)
TOKEN_PATTERN = re.compile(r"(?<![A-Za-z])[a-z]{3,8}(?![A-Za-z])")
CONTEXT_PATTERNS = [
    ("wallet_reference", "Wallet application or backup reference", r"\b(?:wallet\.dat|default_wallet|electrum|metamask|exodus|wasabi|sparrow|bitcoin[ -]core|monero|dogecoin|litecoin)\b", "crypto"),
    ("recovery_reference", "Recovery phrase or private-key reference", r"\b(?:seed[ _-]phrase|recovery[ _-]phrase|mnemonic|private[ _-]key|xprv|wallet[ _-]backup)\b", "crypto"),
    ("mining_reference", "Mining software reference", r"\b(?:cgminer|bfgminer|xmrig|ethminer|minerd|stratum\+tcp)\b", "crypto"),
    ("backup_reference", "Backup or encrypted-container reference", r"\b(?:Time Machine|WindowsImageBackup|VeraCrypt|TrueCrypt|restic|borgbackup)\b", "interesting"),
    ("private_key_header", "Private-key container header", r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----", "interesting"),
    ("bitcoin_database_record", "Possible Bitcoin wallet database record", r"\b(?:walletdescriptorckey|walletdescriptorkey|bestblock_nomerkle|keymeta)\b", "crypto"),
]
COMPILED_CONTEXT = [(kind, title, re.compile(pattern, re.I), category) for kind, title, pattern, category in CONTEXT_PATTERNS]
HEX_KEY = re.compile(r'''(?:private[_ -]?key|privkey)["'\s:=]{1,12}(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])''', re.I)
ETH_ADDRESS = re.compile(r"(?<![A-Za-z0-9])0x[0-9a-fA-F]{40}(?![A-Za-z0-9])")


def text_hits(text):
    for match in BASE58_PATTERN.finditer(text):
        token = match.group()
        payload = base58check(token)
        if payload is None:
            continue
        kind = title = None
        secret = False
        if len(payload) in (33, 34) and payload[0] in (0x80, 0xEF):
            if len(payload) == 34 and payload[-1] != 1:
                continue
            if not 0 < int.from_bytes(payload[1:33], "big") < ORDER:
                continue
            kind, title, secret = "wif_private_key", "WIF private-key candidate", True
        elif len(payload) == 78:
            version = int.from_bytes(payload[:4], "big")
            if payload[4] == 0 and payload[5:13] != b"\0" * 8:
                continue
            if version in EXT_PRIVATE and payload[45] == 0 and 0 < int.from_bytes(payload[46:], "big") < ORDER:
                kind, title, secret = "extended_private_key", "Extended private-key candidate", True
            elif version in EXT_PUBLIC and payload[45] in (2, 3):
                kind, title = "extended_public_key", "Extended public-key candidate"
        elif len(payload) == 21 and payload[0] in (0, 5, 111, 196):
            kind, title = "bitcoin_address", "Bitcoin-format public address"
        if kind:
            yield Hit(kind, title, token.encode(), *match.span(), "high",
                      "Base58Check and supported payload structure valid; ownership/funds not established", secret=secret)
    for match in BECH32_PATTERN.finditer(text):
        if valid_bech32(match.group()):
            yield Hit("bitcoin_address", "Bitcoin witness address", match.group().lower().encode(),
                      *match.span(), "high", "Bech32/Bech32m checksum and witness structure valid; ownership unknown")
    for match in HEX_KEY.finditer(text):
        value = match.group(1)
        if 0 < int(value, 16) < ORDER:
            yield Hit("contextual_hex_key", "Possible hexadecimal private key", value.lower().encode(),
                      *match.span(1), "medium", "Key label and scalar range valid; no checksum or ownership proof", secret=True)
    for match in ETH_ADDRESS.finditer(text):
        yield Hit("ethereum_address", "Ethereum-format address candidate", match.group().encode(),
                  *match.span(), "lead", "40 hexadecimal digits; network, checksum and ownership unverified")
    run = deque(maxlen=24)
    previous_end = None
    for token in TOKEN_PATTERN.finditer(text):
        word = token.group()
        if word not in WORD_INDEX:
            run.clear()
            previous_end = None
            continue
        if previous_end is not None and not re.fullmatch(r"[\s,;\"']{1,16}", text[previous_end:token.start()]):
            run.clear()
        run.append((word, token.start(), token.end()))
        previous_end = token.end()
        for length in (24, 21, 18, 15, 12):
            if len(run) < length:
                continue
            candidate = list(run)[-length:]
            words = [part[0] for part in candidate]
            if valid_mnemonic(words):
                yield Hit("bip39_seed", f"{length}-word BIP39 seed candidate", " ".join(words).encode(),
                          candidate[0][1], candidate[-1][2], "medium",
                          "English BIP39 checksum valid; examples and accidental matches are possible", secret=True)
    for kind, title, pattern, category in COMPILED_CONTEXT:
        for match in pattern.finditer(text):
            yield Hit(kind, title, match.group().lower().encode(), *match.span(), category=category)


def scan_bytes(data: bytes):
    # Only printable spans can contain the supported text encodings. Avoid
    # running every text detector over zero-filled and binary regions of a disk.
    for run in re.finditer(rb"[\x09\x0a\x0d\x20-\x7e]{6,}", data):
        for hit in text_hits(run.group().decode("ascii")):
            hit.start += run.start()
            hit.end += run.start()
            yield hit
    # UTF-16 ASCII runs are decoded separately,
    # including odd-aligned strings, with exact source offsets preserved.
    for pattern, encoding in ((rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){8,}", "utf-16le"),
                              (rb"(?:\x00[\x09\x0a\x0d\x20-\x7e]){8,}", "utf-16be")):
        for run in re.finditer(pattern, data):
            text = run.group().decode(encoding)
            for hit in text_hits(text):
                hit.start = run.start() + hit.start * 2
                hit.end = run.start() + hit.end * 2
                yield hit


def redact(text: str) -> str:
    # All long hex/Base58 tokens are masked, including invalid/partial keys.
    text = re.sub(r"(?<![A-Za-z0-9])[0-9a-fA-F]{64,}(?![A-Za-z0-9])", "[REDACTED HEX]", text)
    text = BASE58_PATTERN.sub("[REDACTED TOKEN]", text)
    # Mask runs of seed-list words even when their checksum is damaged.
    runs = []
    start = end = None
    count = 0
    for token in TOKEN_PATTERN.finditer(text):
        if token.group() in WORD_INDEX and (end is None or re.fullmatch(r"[\s,;\"']{1,16}", text[end:token.start()])):
            start = token.start() if count == 0 else start
            end = token.end()
            count += 1
        else:
            if count >= 8:
                runs.append((start, end))
            count = 1 if token.group() in WORD_INDEX else 0
            start = token.start() if count else None
            end = token.end() if count else None
    if count >= 8:
        runs.append((start, end))
    for start, end in reversed(runs):
        text = text[:start] + "[REDACTED WORD SEQUENCE]" + text[end:]
    return text


def structured_hits(data: bytes):
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError, RecursionError):
        return []
    if not isinstance(value, dict):
        return []
    crypto = value.get("crypto", value.get("Crypto"))
    if isinstance(crypto, dict) and value.get("version") == 3 and all(k in crypto for k in ("cipher", "ciphertext", "kdf", "mac")):
        return [Hit("ethereum_keystore", "Ethereum V3 keystore candidate", data, 0, len(data), "high",
                    "Expected JSON fields present; password/MAC validation still required", secret=True)]
    if "wallet_type" in value and ("keystore" in value or "seed_version" in value):
        return [Hit("electrum_wallet", "Electrum wallet JSON candidate", data, 0, len(data), "high",
                    "Wallet schema indicators present; keys and encryption not validated", secret=True)]
    if all(k in value for k in ("data", "iv", "salt")):
        return [Hit("encrypted_vault", "Encrypted JSON vault candidate", data, 0, len(data), "medium",
                    "Generic encrypted-vault fields; application not established", secret=True)]
    return []
