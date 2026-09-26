"""Evidence ranking is separate from detection: keep observations, surface leads."""
from __future__ import annotations

import re

BACKGROUND = {"interesting_path", "backup_reference", "mining_reference", "recovery_reference",
              "wallet_reference", "browser_history_database", "crypto_browser_domain", "archive_limit"}


def context_flags(data):
    text = data.decode("latin1").lower()
    text += " " + data.decode("utf-16le", errors="ignore").lower()
    text += " " + data[1:].decode("utf-16le", errors="ignore").lower()
    flags = []
    if re.search(r"<(?:ftstext|vtopic|keyword|attr)\b", text):
        flags.append("help-index markup")
    if re.search(r"\b(?:secp\d+[a-z0-9]*|sha1|sha-1|openssl|prime192v1)\b", text) and len(re.findall(r"0x[0-9a-f]{40}\b", text)) >= 3:
        flags.append("cryptography constants in code")
    if re.search(r"\b(?:test vector|test mnemonic|example mnemonic|public test data only)\b", text):
        flags.append("test/example context")
    if re.search(r"(?:wallet\.dat|default_wallet|\"wallet_type\"|\"seed_version\"|\"keystore\")", text):
        flags.append("wallet-specific context")
    return flags


def assessment(finding, validation=None):
    kind = finding["kind"]
    validation = validation or {}
    flags = sorted(set(validation.get("context_flags", [])))
    result = {"tier": "background", "reason": "Supporting observation; no wallet or key established"}
    if kind in BACKGROUND:
        return result
    if kind == "wallet_path":
        paths = " ".join(s.get("path", "") for s in finding["sources"])
        if re.search(r"(?:wallet\.dat|default_wallet|[/\\]electrum[/\\].*wallet|UTC--)", paths, re.I):
            return {"tier": "lead", "reason": "Wallet-specific filename; inspect recovered contents automatically on recovery"}
        return {"tier": "background", "reason": "Broad filename match only"}
    if validation.get("status") == "invalid":
        return {"tier": "background", "reason": validation.get("summary", "Validation failed")}
    if validation.get("known_example"):
        return {"tier": "background", "reason": "Known public test key/seed; retained for reference"}
    if any(flag in flags for flag in ("help-index markup", "cryptography constants in code", "test/example context")):
        return {"tier": "background", "reason": "Likely incidental/example material: " + ", ".join(flags)}
    if kind in ("wif_private_key", "extended_private_key", "bip39_seed", "contextual_hex_key",
                "ethereum_keystore", "electrum_wallet"):
        result = {"tier": "attention" if validation.get("status") in ("valid", "encrypted") else "lead",
                  "reason": validation.get("summary", "Key/wallet candidate awaiting automatic validation")}
    elif kind in ("bitcoin_address", "extended_public_key", "ethereum_address"):
        result = {"tier": "lead", "reason": validation.get("summary", "Public-address candidate; funds not checked")}
    elif kind in ("private_key_header", "encrypted_vault", "bitcoin_database_record"):
        result = {"tier": "lead", "reason": "Container/database lead; not yet an established cryptocurrency wallet"}
    if validation.get("overlapping_seed") and result["tier"] == "attention":
        result = {"tier": "lead", "reason": "Overlapping checksum-valid word sequences; possible incidental match"}
    return result
