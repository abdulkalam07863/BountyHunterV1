import pathlib, sys

root = pathlib.Path(".").resolve()
misses = []

def sub(rel, old, new, label):
    p = root / rel
    t = p.read_text(encoding="utf-8")
    if new in t:
        print(f"SKIP {label}"); return
    if old not in t:
        print(f"MISS {label}"); misses.append(label); return
    p.write_text(t.replace(old, new, 1), encoding="utf-8")
    print(f"OK   {label}")

sub("verify.py",
    "import bh  # noqa: F401  (loads .env)\nfrom __future__ import annotations",
    "from __future__ import annotations\n\nimport bh  # noqa: F401  (loads .env)",
    "verify.py future import")

sub("bh/cli.py",
    'if str(t_.get("status", "")).startswith(("rc=", "crash", "no sources"))]',
    'if str(t_.get("status", "")).startswith(("rc=", "crash"))]',
    "dead-tool classifier")

sub("bh/cli.py",
    "    findings, cloned, failed = [], [], []",
    "    findings, cloned, failed, degraded = [], [], [], []",
    "degraded counter")

sub("bh/cli.py",
    '''        dead = _dead_tools(res["tools"])
        if dead:
            console.print(f"[red]{dest.name}: {', '.join(dead)} failed - tree not compiled[/]")
            failed.append(dest.name)
            continue
        for f in res["findings"]:
            f["file"] = f"{dest.name}/{f.get('file') or ''}"
        findings.extend(res["findings"])''',
    '''        dead = _dead_tools(res["tools"])
        if dead:
            console.print(f"[yellow]{dest.name}: {', '.join(dead)} degraded - findings kept[/]")
            degraded.append(dest.name)
        for f in res["findings"]:
            f["file"] = f"{dest.name}/{f.get('file') or ''}"
        findings.extend(res["findings"])''',
    "keep findings on degraded repos")

sub("bh/cli.py",
    '''    if failed:
        console.print(f"\\n[red]{len(failed)} of {len(cloned) + len(failed)} repos failed "
                      f"- see the warnings above[/]")''',
    '''    if degraded:
        console.print(f"\\n[yellow]{len(degraded)} of {len(cloned)} repos degraded "
                      f"- findings kept, coverage reduced[/]")''',
    "degraded summary")

sub("bh/audit/solidity.py",
    "import json\nimport tempfile",
    "import json\nimport re\nimport tempfile",
    "import re")

sub("bh/audit/solidity.py",
    '_TOML = """[profile.default]',
    '_SIZE_RX = re.compile(r"exceed[s]?.*size limit", re.I)\n\n_TOML = """[profile.default]',
    "size-limit regex")

sub("bh/audit/solidity.py",
    'oversize = "exceeds the size limit" in (res["out"] + res["err"])',
    'oversize = bool(_SIZE_RX.search(res["out"] + res["err"]))',
    "oversize detection")

sub("bh/audit/solidity.py",
    '''    return findings, {"tool": "slither", "status": "ok" if findings else _status(res),
                      "dur": res["dur"], "err": (res["err"] or "")[:400]}''',
    '''    status = "ok" if findings else ("empty" if res["ok"] else _status(res))
    return findings, {"tool": "slither", "status": status,
                      "dur": res["dur"], "err": (res["err"] or "")[:400]}''',
    "slither exit code")

sub("bh/audit/tools.py",
    '''    res = run_cmd(["semgrep", "--json", "--quiet", "--config", "auto", "--config", str(rules_dir),
                   "--max-target-bytes", str(cfg.audit.get("max_file_bytes", 2_000_000)),
                   "--output", out, "."], cwd=repo,''',
    '''    excludes = []
    for d in cfg.audit.get("exclude_dirs", []):
        excludes += ["--exclude", d]
    res = run_cmd(["semgrep", "--json", "--quiet", "--config", str(rules_dir), *excludes,
                   "--max-target-bytes", str(cfg.audit.get("max_file_bytes", 2_000_000)),
                   "--output", out, "."], cwd=repo,''',
    "semgrep excludes")

sub("bh/audit/triage.py",
    '        key = f.get("tool") or "?"',
    '        key = f"{f.get(\'tool\')}::{f.get(\'title\')}"',
    "cap per rule not per tool")

sub("config.yaml",
    "  severity_floor: low",
    "  severity_floor: low\n  max_hits_per_rule: 6\n  max_total_findings: 400",
    "config caps in audit block")

print()
if misses:
    print("MISSES:", ", ".join(misses)); sys.exit(1)
print("all patches applied")
