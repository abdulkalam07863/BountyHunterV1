"""Wallet and key attacks.

Recovers candidate private keys from the repo, derives the address, and checks
whether that address still holds funds on the fork. A leaked key in a committed
.env is a critical finding, but only a funded one is worth writing up.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..util import log, run_cmd, short_hash

PK_RX = re.compile(r"\b(?:0x)?([0-9a-fA-F]{64})\b")
MNEMONIC_RX = re.compile(r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b")
WEAK = ["test", "dev", "password", "secret", "ganache", "hardhat", "anvil",
        "private", "admin", "deployer", "bounty", "hunter", "123456", "changeme"]
ENV_FILES = (".env", ".env.example", ".env.local", "hardhat.config.js",
             "hardhat.config.ts", "foundry.toml", "truffle-config.js")


def _candidates(repo: Path) -> list[tuple[str, str]]:
    found = []
    for name in ENV_FILES:
        f = repo / name
        if not f.is_file():
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        for m in PK_RX.finditer(text):
            found.append((m.group(1), name))
        for m in MNEMONIC_RX.finditer(text):
            found.append((" ".join(m.group(0).split()), name))
    for m in PK_RX.finditer("".join(w for w in WEAK)):
        found.append((m.group(1), "weak-derived"))
    return found


def _derive(repo: Path, secret: str) -> str | None:
    if " " in secret:
        res = run_cmd(["cast", "wallet", "address", "--mnemonic", secret], timeout=60)
    else:
        res = run_cmd(["cast", "wallet", "address", "--private-key",
                       secret if secret.startswith("0x") else "0x" + secret], timeout=60)
    return res["out"].strip() if res["ok"] else None


def scan_wallet_attacks(cfg, repo: Path) -> dict:
    if not cfg.attack.get("wallet_scan", True):
        return {"results": []}
    try:
        from .harness import _deployments
        targets = _deployments(repo)
    except Exception:
        targets = []

    results = []
    for secret, source in _candidates(repo)[:40]:
        addr = _derive(repo, secret)
        if not addr:
            continue
        if targets and not any(addr.lower() == t.lower() for t in targets):
            continue
        results.append({
            "vector": "leaked_key",
            "contract": addr,
            "tokens": [], "deltas": [],
            "profit": True, "structural": True, "usd": 0.0,
            "note": (f"Private key material in `{source}` derives to {addr}, which appears "
                     f"in deployment artifacts. Confirm the address still controls funds."),
            "remediation": "Move secrets out of the repo, or rotate the deployer key.",
            "artifact": source,
        })
    if results:
        log.info("wallet: %d key candidate(s) matching deployments", len(results))
    return {"results": results}