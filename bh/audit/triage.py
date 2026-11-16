from __future__ import annotations

import concurrent.futures as cf
from pathlib import Path

from ..util import log
from . import defi_rules, scan, solidity, tools

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
BASE_CVSS = {"critical": 9.4, "high": 7.8, "medium": 5.4, "low": 2.9, "info": 0.0}
CONF_ADJ = {"high": 0.4, "medium": 0.0, "low": -0.6}


def cvss_for(severity: str, confidence: str) -> float:
    return round(max(0.0, min(10.0, BASE_CVSS.get(severity, 5.0) + CONF_ADJ.get(confidence, 0.0))), 1)


def economic_multiplier(f: dict) -> float:
    base = {"reentrancy": 1.35, "oracle": 1.4, "flashloan": 1.35, "accounting": 1.3,
            "precision": 1.2, "signature": 1.3, "upgrade": 1.25,
            "access-control": 1.3, "exploit": 1.4}.get(f.get("category", ""), 1.0)
    return base * (1 + 0.1 * (int(f.get("economic", 1)) - 1))


def normalise(f: dict) -> dict:
    sev = str(f.get("severity") or "medium").lower().strip()
    sev = {"moderate": "medium", "error": "high", "warning": "medium", "note": "low"}.get(sev, sev)
    f["severity"] = sev if sev in SEVERITY_ORDER else "medium"
    conf = str(f.get("confidence") or "medium").lower()
    f["confidence"] = conf if conf in CONF_ADJ else "medium"
    f["cvss"] = round(min(10.0, cvss_for(f["severity"], f["confidence"]) * economic_multiplier(f)), 1)
    return f


def dedupe(findings: list) -> list:
    best = {}
    for f in findings:
        key = f"{f.get('file')}::{f.get('tool')}::{(f.get('title') or '')[:40].lower()}"
        if key not in best or f["cvss"] > best[key]["cvss"]:
            best[key] = f
    return list(best.values())


def cap_per_rule(findings: list, cap: int = 3, max_total: int = 120) -> list:
    counts: dict = {}
    out = []
    for f in findings:
        key = f.get("tool") or "?"
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= cap:
            out.append(f)
        if len(out) >= max_total:
            break
    return out


def _norm_path(p: str) -> str:
    return (p or "").replace("\\", "/").lstrip("./").strip("/")


def in_scope(f: dict, scope_paths) -> bool:
    if not scope_paths:
        return True
    path = _norm_path(f.get("file") or "")
    if not path:
        return True
    for p in scope_paths:
        p = _norm_path(p)
        if p and (path == p or path.startswith(p + "/")):
            return True
    return False


def _record(name, fut_or_result, all_findings, tool_report):
    try:
        found, meta = fut_or_result
    except Exception as exc:
        tool_report.append({"tool": name, "status": f"crash: {exc}"})
        log.info("%s -> crash: %s", name, exc)
        return
    all_findings.extend(found)
    tool_report.append(meta)
    log.info("%s -> %d (%s)", name, len(found), meta.get("status"))


def run_audit(cfg, repo: Path, rules_dir: Path, solidity_mode: bool = False,
              scope_paths=None) -> dict:
    from ..attack import attack_cfg

    enabled = {k for k, v in (cfg.audit.get("tools") or {}).items() if v}
    sol_enabled = {k for k, v in (cfg.solidity.get("tools") or {}).items() if v} if solidity_mode else set()
    all_findings, tool_report = [], []

    # forge build first, alone: slither's crytic_compile re-runs the build and
    # collides with an in-flight one over the same out/ directory.
    if "forge_build" in sol_enabled:
        try:
            _record("forge-build", solidity.RUNNERS["forge_build"](repo, cfg),
                    all_findings, tool_report)
        except Exception as exc:
            tool_report.append({"tool": "forge-build", "status": f"crash: {exc}"})

    with cf.ThreadPoolExecutor(max_workers=max(1, cfg.max_concurrency)) as pool:
        futures = {}
        for name in enabled:
            if name not in tools.RUNNERS:
                continue
            if name == "semgrep":
                futures[pool.submit(tools.RUNNERS[name], repo, cfg, rules_dir)] = name
            else:
                futures[pool.submit(tools.RUNNERS[name], repo, cfg)] = name
        for name in sol_enabled - {"forge_build"}:
            if name in solidity.RUNNERS:
                futures[pool.submit(solidity.RUNNERS[name], repo, cfg)] = name
        for fut in cf.as_completed(futures):
            _record(futures[fut], fut.result(), all_findings, tool_report)

    if cfg.audit.get("custom_rules", True):
        hits = scan.run_rules(repo, cfg)
        all_findings.extend(hits)
        tool_report.append({"tool": "custom-rules", "status": "ok", "count": len(hits)})
        log.info("custom rules -> %d", len(hits))
    if solidity_mode:
        hits = defi_rules.run(repo, cfg)
        all_findings.extend(hits)
        tool_report.append({"tool": "defi-rules", "status": "ok", "count": len(hits)})
        log.info("defi rules -> %d", len(hits))

    # Active exploitation runs last: it needs a compiled tree, and its findings
    # must survive the severity floor and per-rule cap, so it is appended after
    # the static passes rather than inside the thread pool.
    if attack_cfg(cfg).get("enabled", False):
        try:
            from ..attack import run_attacks
            hits, meta = run_attacks(cfg, repo, scope_paths)
            all_findings.extend(hits)
            tool_report.append(meta)
        except Exception as exc:
            tool_report.append({"tool": "attack", "status": f"crash: {exc}"})
            log.warning("attack layer crashed: %s", exc)

    floor = SEVERITY_ORDER.get(str(cfg.audit.get("severity_floor", "low")).lower(), 1)
    norm = [normalise(f) for f in all_findings]
    norm = dedupe([f for f in norm if SEVERITY_ORDER[f["severity"]] >= floor])
    norm = [f for f in norm if in_scope(f, scope_paths)]
    norm.sort(key=lambda f: (-f["cvss"], f.get("file") or "", f.get("line") or 0))
    norm = cap_per_rule(norm,
                        int(cfg.audit.get("max_hits_per_rule", 3)),
                        int(cfg.audit.get("max_total_findings", 120)))

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in norm:
        counts[f["severity"]] += 1
    for i, f in enumerate(norm, 1):
        f["fid"] = f"{f['severity'][:4].upper()}-{i:03d}"
    return {"findings": norm, "counts": counts, "tools": tool_report}