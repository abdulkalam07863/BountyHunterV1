"""Active exploitation layer.

Static tools guess. This module executes. Every vector runs against a fork,
funds a throwaway attacker, and measures actual balance delta. A vector that
ends with the attacker holding more than it started is a proven fund path,
not a hunch.
"""
from __future__ import annotations

from pathlib import Path

from ..util import log, resolve_rpc, short_hash
from .cfg import attack_cfg

SEV = [(100_000, "critical"), (5_000, "high"), (250, "medium"), (0, "low")]


def _rank(s: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0)


def _severity(usd: float, structural: bool) -> str:
    for floor, sev in SEV:
        if usd >= floor:
            return sev if not structural else max(sev, "high", key=_rank)
    return "medium"


def _finding(r: dict) -> dict:
    usd = r.get("usd", 0.0)
    sev = _severity(usd, bool(r.get("structural")))
    deltas = ", ".join(f"{t}:{d:+.6g}" for t, d in zip(r.get("tokens", []), r.get("deltas", [])))
    return {
        "title": f"Proven fund path: {r['vector']} on {r.get('contract') or 'target'}",
        "severity": sev,
        "confidence": "high" if usd > 0 else "medium",
        "category": "exploit",
        "cwe": "CWE-682" if "rounding" in r["vector"] else "CWE-841",
        "file": r.get("artifact"),
        "line": None,
        "code": (r.get("note") or "")[:600],
        "detail": (f"Vector `{r['vector']}` executed against a fork. "
                   f"Attacker balance delta: {deltas or 'none'}. "
                   f"Estimated gross: ${usd:,.0f}.\n\n{r.get('note') or ''}"),
        "remediation": r.get("remediation", ""),
        "tool": f"attack:{r['vector']}",
        "economic": 3,
        "references": [],
        "fingerprint": short_hash(
            f"attack:{r['vector']}:{r.get('contract')}:{r.get('artifact')}"),
    }


def run_attacks(cfg, repo: Path, scope_paths=None) -> tuple[list, dict]:
    from .harness import run_harness
    from .wallet import scan_wallet_attacks

    ac = attack_cfg(cfg)
    if not ac.get("enabled", False):
        return [], {"tool": "attack", "status": "disabled"}

    rpc = resolve_rpc(cfg)
    if not rpc:
        return [], {"tool": "attack", "status": "no rpc"}

    results, meta = run_harness(cfg, repo, rpc, scope_paths)

    wallet = scan_wallet_attacks(cfg, repo)
    results.extend(wallet["results"])

    findings = [_finding(r) for r in results if r.get("profit") or r.get("structural")]
    findings.sort(key=lambda f: -_rank(f["severity"]))
    log.info("attack: %d vector(s), %d proven", len(results), len(findings))
    return findings, {"tool": "attack", "status": meta.get("status", "ok"),
                      "vectors": len(results), "proven": len(findings),
                      "skipped": meta.get("skipped", 0)}


__all__ = ["run_attacks", "attack_cfg"]