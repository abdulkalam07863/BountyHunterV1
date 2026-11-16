"""Solidity / DeFi heuristics, economically weighted."""
from __future__ import annotations

import re
from dataclasses import dataclass

SKIP_DIRS = {"mocks", "test", "tests", "lib", "node_modules", ".git", "interfaces",
             "audit-reports", "deployments", "scripts", "out", "cache"}


@dataclass(frozen=True)
class SRule:
    id: str
    title: str
    severity: str
    category: str
    cwe: str
    confidence: str
    pattern: str
    detail: str
    remediation: str
    economic: int = 1


RULES = [
    SRule("SOL-REENT", "State update after external call", "high", "reentrancy", "CWE-841", "medium",
          r"(?:safeTransfer|transfer|\.call\(|safeTransferFrom)[^;]*;\s*\n(?:[^\n]*\n){0,6}?[^\n]*\b(balanceOf|totalSupply|totalAssets|_balances\[|shares\[)[^\n]*=",
          "External interaction precedes an accounting write.", "Checks-effects-interactions or nonReentrant.", 3),
    SRule("SOL-NONREENT", "External call without guard in sight", "medium", "reentrancy", "CWE-841", "low",
          r"function\s+\w+[^{]*external[^{]*\{(?:(?!nonReentrant)[\s\S]){0,400}?\.call\{",
          "External transfer with no visible guard.", "Add nonReentrant.", 2),
    SRule("SOL-REENT-TOKEN", "Callback-capable token handling", "medium", "reentrancy", "CWE-841", "low",
          r"(onERC721Received|onERC1155Received|tokensReceived|ERC777)",
          "Recipient code runs mid-transfer.", "Assume hook reentrancy.", 2),
    SRule("SOL-DIV-BEFORE-MUL", "Division before multiplication", "medium", "precision", "CWE-682", "medium",
          r"\w+\s*/\s*\w+[^;\n]*\*", "Truncation then amplification.", "Multiply first.", 2),
    SRule("SOL-ROUND-DOWN", "Rounding direction unchecked", "medium", "precision", "CWE-682", "low",
          r"(shares|amount)\s*=\s*[^;\n]*(mulDiv|/\s*totalSupply|/\s*totalAssets)",
          "Verify rounding favours protocol.", "Round down on deposit.", 2),
    SRule("SOL-UNSAFE-CAST", "Unsafe downcast", "medium", "precision", "CWE-197", "medium",
          r"\b(uint(?:8|16|32|64|96|128)|int(?:8|16|32|64|128))\s*\(\s*\w+\s*\)",
          "Silent truncation.", "SafeCast.", 2),
    SRule("SOL-PRICE-PER-SHARE", "Exchange rate computation", "medium", "accounting", "CWE-682", "low",
          r"(pricePerShare|exchangeRate|convertTo(?:Shares|Assets)|getRate)\s*\(",
          "Inflation / donation attacks live here.", "Virtual offsets or dead shares.", 3),
    SRule("SOL-SPOT-ORACLE", "Spot price used as oracle", "high", "oracle", "CWE-829", "medium",
          r"(getReserves|slot0|getSpotPrice|price0Cumulative)",
          "Spot reads are flash-loan manipulable.", "Use TWAP with staleness bounds.", 3),
    SRule("SOL-ORACLE-STALE", "Chainlink answer without staleness check", "high", "oracle", "CWE-829", "medium",
          r"latestRoundData\s*\([^)]*\)\s*;(?:(?!updatedAt|answeredInRound)[\s\S]){0,200}",
          "Missing updatedAt validation.", "Check age and answer > 0.", 3),
    SRule("SOL-ORACLE-DECIMALS", "Oracle decimals assumed", "medium", "oracle", "CWE-704", "medium",
          r"(10\s*\*\*\s*(?:18|8)|1e18\s*/\s*price|price\s*\*\s*1e\d+)",
          "Hardcoded scaling.", "Read decimals().", 2),
    SRule("SOL-TX-ORIGIN", "tx.origin authorisation", "medium", "access-control", "CWE-477", "high",
          r"tx\.origin", "Phishing-vulnerable.", "Use msg.sender.", 1),
    SRule("SOL-MISSING-AUTH", "Privileged function body has no inline check", "medium",
          "access-control", "CWE-284", "low",
          r"function\s+\w+[^{]*\b(onlyOwner|onlyAdmin|onlyRole)\b[^{]*\{(?:(?!require\(|if\s*\(|onlyOwner|onlyAdmin|onlyRole)[\s\S]){0,220}\}",
          "Modifier gates the call, but the body has no inline invariant check. Confirm every branch is guarded.",
          "Add an explicit require on the critical argument, or document why the modifier suffices.", 2),
    SRule("SOL-UNPROTECTED-INIT", "Initializer without modifier", "critical", "access-control", "CWE-665", "medium",
          r"function\s+(?:initialize|init)\s*\((?:(?!initializer)[\s\S]){0,200}\{",
          "Anyone can re-initialise.", "Add initializer and _disableInitializers.", 3),
    SRule("SOL-DELEGATECALL", "delegatecall to variable target", "high", "access-control", "CWE-829", "medium",
          r"delegatecall\s*\(", "Malicious target owns storage.", "Allow-list targets.", 3),
    SRule("SOL-STORAGE-GAP", "Upgradeable storage layout", "high", "upgrade", "CWE-665", "medium",
          r"(__gap|_gap)\s*\[", "Gaps must match on upgrade.", "Preserve gap sizes.", 2),
    SRule("SOL-SELFDESTRUCT", "selfdestruct / force-send ETH", "low", "upgrade", "CWE-665", "medium",
          r"(selfdestruct|payable\([^)]*\)\.transfer|address\(this\)\.balance)",
          "ETH can be force-fed.", "Track internal accounting.", 2),
    SRule("SOL-UNCHECKED-TRANSFER", "Unchecked ERC20 return", "medium", "integration", "CWE-252", "medium",
          r"(?<!require\()\b\w+\.transfer(?:From)?\s*\([^)]*\)\s*;", "Silent failure.", "SafeERC20.", 2),
    SRule("SOL-FEE-ON-TRANSFER", "Balance-delta assumption", "high", "integration", "CWE-682", "medium",
          r"(amountIn|amountOut)[^;\n]*=\s*\w+\.balanceOf\(", "Fee-on-transfer breaks accounting.",
          "Measure deltas.", 2),
    SRule("SOL-APPROVE-RACE", "approve without zero-reset", "low", "integration", "CWE-362", "low",
          r"\.approve\s*\(", "Front-runnable on some tokens.", "Set to 0 or forceApprove.", 1),
    SRule("SOL-FLASHLOAN", "Flash loan entrypoint", "high", "flashloan", "CWE-829", "medium",
          r"(flashLoan|receiveFlashLoan|onFlashLoan|executeOperation)\s*\(",
          "State must survive a borrow/repay cycle.", "Verify invariants.", 3),
    SRule("SOL-ECDSA", "Raw ecrecover", "high", "signature", "CWE-347", "medium",
          r"ecrecover\s*\(", "Returns address(0) on failure.", "Use ECDSA.recover.", 2),
    SRule("SOL-SIG-REPLAY", "Signed payload without visible nonce", "high", "signature", "CWE-294", "low",
          r"(?:ecrecover|ECDSA\.recover)[\s\S]{0,400}(?!nonce)",
          "Verify the digest includes a per-signer nonce, chainId and verifying contract.",
          "Bind nonce, chainId and address(this) into the signed struct.", 3),
    SRule("SOL-LOOP-LENGTH", "Loop bounded by array length", "medium", "dos", "CWE-400", "low",
          r"for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length", "Unbounded growth.", "Bound the batch.", 2),
    SRule("SOL-UNBOUNDED-PUSH", "Array push in loop", "medium", "dos", "CWE-400", "medium",
          r"for\s*\([^)]*\)\s*\{[^}]*\.push\(", "Array grows without pruning.", "Add removal paths.", 2),
    SRule("SOL-TODO", "Security TODO", "low", "hygiene", "CWE-1059", "low",
          r"(TODO|FIXME|XXX)[^\n]{0,90}(secur|valid|check|auth|oracle)", "Incomplete control.", "Verify.", 1),
    SRule("SOL-MAGIC-NUMBER", "Unnamed hardcoded constant", "low", "hygiene", "CWE-547", "low",
          r"(?<![\w.])(?:1e\d{2}|[1-9]\d{5,})(?![\w.])", "Hides unit assumptions.", "Name it.", 1),
]


def _snippet(text, idx, pad=3):
    line = text.count("\n", 0, idx) + 1
    lines = text.splitlines()
    lo, hi = max(0, line - 1 - pad), min(len(lines), line + pad)
    return line, "\n".join(f"{i + 1:>5} | {lines[i]}" for i in range(lo, hi))


def run(repo, cfg) -> list:
    from ..util import short_hash
    out, caps = [], {}
    per_file = int(cfg.solidity.get("max_hits_per_rule_per_file", 2))
    for path in repo.rglob("*.sol"):
        if any(p in SKIP_DIRS for p in path.parts):
            continue
        if cfg.solidity.get("skip_mocks", True) and path.name.startswith("Mock"):
            continue
        if cfg.solidity.get("skip_interfaces", True) and path.name.startswith("I") and path.name[1:2].isupper():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(repo).as_posix()
        for r in RULES:
            if caps.get(r.id, 0) >= 60:
                continue
            local = 0
            for m in re.compile(r.pattern, re.S | re.M).finditer(text):
                if caps.get(r.id, 0) >= 60 or local >= per_file:
                    break
                line, snip = _snippet(text, m.start())
                out.append({"title": r.title, "severity": r.severity, "confidence": r.confidence,
                            "category": r.category, "cwe": r.cwe, "file": rel, "line": line,
                            "code": snip, "detail": r.detail, "remediation": r.remediation,
                            "tool": f"defi:{r.id}", "economic": r.economic,
                            "references": [f"https://cwe.mitre.org/data/definitions/{r.cwe.split('-')[1]}.html"],
                            "fingerprint": short_hash(f"{r.id}:{rel}:{line}")})
                caps[r.id] = caps.get(r.id, 0) + 1
                local += 1
    return out
