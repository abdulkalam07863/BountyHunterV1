from __future__ import annotations

import fnmatch
from pathlib import Path

from ..util import log, short_hash
from .rules import RULES, SKIP_DIRS, SKIP_EXT

MAX_HITS = 60


def walk(repo: Path, max_bytes: int, exclude):
    skip = SKIP_DIRS | set(exclude or [])
    for path in repo.rglob("*"):
        if not path.is_file() or any(p in skip for p in path.parts):
            continue
        if path.suffix.lower() in SKIP_EXT:
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        yield path


def _match(path: Path, repo: Path, globs) -> bool:
    if globs == ("*",):
        return True
    rel = path.relative_to(repo).as_posix()
    return any(fnmatch.fnmatch(rel, g) if "/" in g else fnmatch.fnmatch(path.name, g)
               for g in globs)


def _snippet(text: str, start: int, pad: int):
    line = text.count("\n", 0, start) + 1
    lines = text.splitlines()
    lo, hi = max(0, line - 1 - pad), min(len(lines), line + pad)
    return line, "\n".join(f"{i + 1:>5} | {lines[i]}" for i in range(lo, hi))


def run_rules(repo: Path, cfg) -> list:
    out, caps = [], {}
    max_bytes = int(cfg.audit.get("max_file_bytes", 2_000_000))
    pad = int(cfg.report.get("snippet_lines", 3))
    per_rule_file = int(cfg.solidity.get("max_hits_per_rule_per_file", 2))
    for path in walk(repo, max_bytes, cfg.audit.get("exclude_dirs", [])):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not text.strip():
            continue
        rel = path.relative_to(repo).as_posix()
        for rule in RULES:
            if caps.get(rule.id, 0) >= MAX_HITS or not _match(path, repo, rule.globs):
                continue
            local = 0
            for m in rule.compiled().finditer(text):
                if caps.get(rule.id, 0) >= MAX_HITS or local >= per_rule_file:
                    break
                line, snip = _snippet(text, m.start(), pad)
                out.append({"title": rule.title, "severity": rule.severity,
                            "confidence": rule.confidence, "category": rule.category,
                            "cwe": rule.cwe, "file": rel, "line": line, "code": snip,
                            "detail": rule.detail, "remediation": rule.remediation,
                            "tool": f"rule:{rule.id}",
                            "references": [f"https://cwe.mitre.org/data/definitions/{rule.cwe.split('-')[1]}.html"],
                            "fingerprint": short_hash(f"{rule.id}:{rel}:{m.group(0)[:80]}")})
                caps[rule.id] = caps.get(rule.id, 0) + 1
                local += 1
    log.info("custom rules: %d hits", len(out))
    return out
