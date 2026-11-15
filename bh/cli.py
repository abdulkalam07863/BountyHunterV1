from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import links
from .attack import run_attacks
from .audit import run_audit
from .clone import CloneError, clone_repo
from .config import Config
from .db import DB
from .discover import run_discovery
from .docs_hunt import hunt
from .intel import detect_stack, find_prior_audits, first_deployment_address, gather
from .poc import generate
from .report import write_index, write_reports
from .target import intake, save_scope
from .util import (BANNER, make_session, project_dir, repo_stats, resolve_rpc,
                   resolve_workspace, setup_logging, slugify)

console = Console()
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _ctx(args):
    cfg = Config.load(args.config)
    setup_logging(args.verbose)
    workspace = resolve_workspace(cfg)
    return cfg, workspace, DB(workspace / "bountyhunter.db"), make_session(
        cfg.rate_limit_rps, cfg.request_timeout, cfg.user_agent)


def _resolve(db, ident: str):
    p = db.get_project(ident)
    if not p:
        console.print(f"[red]no project matching[/] {ident!r}")
        sys.exit(2)
    return p


def _tool_table(name: str, tools_report: list) -> Table:
    t = Table(title=f"{name} - tool status")
    t.add_column("tool")
    t.add_column("status")
    for t_ in tools_report:
        st = str(t_.get("status", "?"))
        colour = "green" if st == "ok" else "red" if ("missing" in st or "rc=" in st or "crash" in st) else "yellow"
        t.add_row(str(t_.get("tool", "?")), f"[{colour}]{st}[/]")
    return t


def _dead_tools(tools_report: list) -> list:
    """Only real failures. bandit/gitleaks/npm exit 1 to mean 'found something'."""
    return [t_.get("tool") for t_ in tools_report
            if str(t_.get("status", "")).startswith(("rc=", "crash", "no sources"))]


def cmd_discover(args):
    cfg, workspace, db, session = _ctx(args)
    for kw in (args.keyword or cfg.keywords):
        console.print(f"[cyan]discovering[/] {kw}")
        r = run_discovery(cfg, db, session, kw, use_x=not args.no_x)
        for src, status in r["sources"].items():
            console.print(f"  {src}: {status}")
    out = workspace / "discovery-links.md"
    out.write_text("\n".join(f"- [{l['label']}]({l['url']})" for l in db.links()), encoding="utf-8")
    console.print(f"[green]links ->[/] {out}")


def cmd_links(args):
    cfg, workspace, db, _ = _ctx(args)
    out = workspace / f"links-{slugify(args.keyword)}.md"
    out.write_text("\n".join(f"- [{l['label']}]({l['url']})"
                             for l in links.for_keyword(args.keyword)), encoding="utf-8")
    console.print(f"[green]->[/] {out}")


def cmd_rpc(args):
    cfg, _, _, session = _ctx(args)
    url = resolve_rpc(cfg)
    if not url:
        console.print("[red]no RPC in .env or config[/]")
        sys.exit(1)
    host = url.split("//")[-1].split("/")[0]
    key = "set" if ("v2/" in url or "v3/" in url) else "absent"
    console.print(f"rpc -> [cyan]{host}[/] (key {key})")
    try:
        r = session.post(url, json={"jsonrpc": "2.0", "id": 1,
                                    "method": "eth_blockNumber", "params": []}, timeout=20)
        data = r.json()
        if "result" in data:
            console.print(f"[green]ok[/] block {int(data['result'], 16):,}")
        else:
            console.print(f"[red]error[/] {data.get('error')}")
    except Exception as exc:
        console.print(f"[red]{type(exc).__name__}: {exc}[/]")


def cmd_list(args):
    cfg, workspace, db, _ = _ctx(args)
    rows = db.list_projects(args.status)
    t = Table(title=f"{len(rows)} projects")
    for c in ("ID", "Platform", "Name", "Repo", "Status"):
        t.add_column(c, overflow="fold")
    for p in rows:
        t.add_row(str(p["id"]), p["platform"], (p["name"] or p["slug"])[:52],
                  (p["repo_url"] or "-")[:52], p["status"])
    console.print(t)


def cmd_show(args):
    cfg, workspace, db, session = _ctx(args)
    p = _resolve(db, args.id)
    intel = gather(cfg, session, p, workspace)
    console.print_json(json.dumps({**dict(p), "intel": intel}, indent=2, default=str))
    if intel["repo_url"]:
        db.upsert_project(p["platform"], p["slug"], repo_url=intel["repo_url"], status="intel")


def cmd_clone(args):
    cfg, workspace, db, session = _ctx(args)
    p = _resolve(db, args.id)
    if not p["repo_url"]:
        intel = gather(cfg, session, p, workspace)
        if not intel["repo_url"]:
            console.print("[red]no repo resolvable[/]")
            sys.exit(1)
        db.upsert_project(p["platform"], p["slug"], repo_url=intel["repo_url"])
        p = db.get_project(args.id)
    dest = project_dir(workspace, p["platform"], p["slug"]) / "repo" / "src"
    try:
        clone_repo(p["repo_url"], None, dest)
    except CloneError as exc:
        console.print(f"[red]{exc}[/]")
        sys.exit(1)
    db.upsert_project(p["platform"], p["slug"], local_path=str(dest), status="cloned")
    console.print(f"[green]cloned ->[/] {dest}")


def cmd_attack(args):
    cfg, workspace, db, _ = _ctx(args)
    p = _resolve(db, args.id)
    repo = Path(p["local_path"]) if p["local_path"] else \
        project_dir(workspace, p["platform"], p["slug"]) / "repo"
    if not repo.exists():
        console.print("[red]no local repo - run `bh clone` first[/]")
        sys.exit(1)
    if not cfg.attack:
        cfg.attack = {}
    cfg.attack["enabled"] = True
    if args.vectors:
        from .attack.vectors import VECTORS
        keep = set(args.vectors)
        for k in [k for k in VECTORS if k not in keep]:
            del VECTORS[k]
        if not VECTORS:
            console.print(f"[red]no vector matched {sorted(keep)}[/]")
            sys.exit(2)

    from .audit.solidity import ensure_foundry_config
    from .util import run_cmd

    if not ensure_foundry_config(repo):
        console.print("[red]no contracts/ or src/ directory - nothing to attack[/]")
        sys.exit(1)

    if not (repo / "lib" / "forge-std").is_dir():
        console.print("[cyan]fetching forge-std[/]")
        r = run_cmd(["forge", "install", "foundry-rs/forge-std", "--no-commit"],
                    cwd=repo, timeout=900)
        if not r["ok"]:
            console.print(f"[red]forge-std install failed:[/] {r['err'][:300]}")
            sys.exit(1)

    console.print(f"[cyan]building[/] {repo.name}")
    b = run_cmd(["forge", "build"], cwd=repo, timeout=1800)
    if not b["ok"]:
        console.print(f"[red]build failed - vectors need a compiling tree[/]")
        console.print(f"[dim]{(b['err'] or b['out'])[:800]}[/]")
        sys.exit(1)

    findings, meta = run_attacks(cfg, repo)
    console.print(_tool_table(repo.name, [meta]))
    if not findings:
        console.print("[yellow]no vector landed - nothing proven on this fork[/]")
    for f in findings:
        colour = "red" if f["severity"] in ("critical", "high") else "yellow"
        console.print(f"[{colour}]{f['severity']:8}[/] {f['title']}")
        console.print(f"         [dim]{(f['code'] or '')[:160]}[/]")
    for f in findings:
        db.add_finding(p["id"], f)
    if findings:
        console.print(f"\n[green]{len(findings)} finding(s) stored[/]")


def cmd_audit(args):
    cfg, workspace, db, _ = _ctx(args)
    p = _resolve(db, args.id)
    pdir = project_dir(workspace, p["platform"], p["slug"])
    repo = Path(p["local_path"]) if p["local_path"] else pdir / "repo"
    if not repo.exists():
        console.print("[red]no local repo - run `bh clone` first[/]")
        sys.exit(1)
    stats = repo_stats(repo)
    db.upsert_project(p["platform"], p["slug"], stack=detect_stack(repo), status="auditing")
    audit = run_audit(cfg, repo, RULES_DIR, solidity_mode=bool(list(repo.rglob("*.sol"))))
    console.print(_tool_table(repo.name, audit["tools"]))
    dead = _dead_tools(audit["tools"])
    if dead:
        console.print(f"[yellow]{', '.join(dead)} failed - findings may be incomplete[/]")
    for f in audit["findings"]:
        db.add_finding(p["id"], f)
    for t in audit["tools"]:
        db.add_run(p["id"], t.get("tool", "?"), t.get("status", "?"))
    for path in write_reports(p, audit, cfg, pdir, stats):
        console.print(f"[green]report ->[/] {path}")
    db.set_status(p["id"], "audited")
    console.print(f"{len(audit['findings'])} findings")


def cmd_target(args):
    cfg, workspace, db, session = _ctx(args)
    console.print(f"[cyan]intake[/] {args.url}")
    pid, scope = intake(cfg, db, session, args.url)

    t = Table(title="parsed scope")
    t.add_column("field")
    t.add_column("value", overflow="fold")
    for r in scope["repos"]:
        t.add_row("repo", r["url"])
        for p_ in r["paths"]:
            t.add_row("", f"  path: {p_}")
        if not r["paths"]:
            t.add_row("", "  (whole repository)")
    t.add_row("ladder", "\n".join(f"{s['severity']}: ${s['max_reward']:,}"
                                  for s in scope["severity_table"]) or "-")
    t.add_row("contacts", ", ".join(scope["contacts"]) or "-")
    t.add_row("exclusions", str(len(scope["exclusions"])))
    console.print(t)

    p = db.get_project(str(pid))
    pdir = project_dir(workspace, p["platform"], p["slug"])
    console.print(f"[green]scope ->[/] {save_scope(pdir, scope)}")
    if not args.go:
        console.print("\n[dim]re-run with --go to clone and audit[/]")
        return

    if not resolve_rpc(cfg):
        console.print("[yellow]no RPC configured - PoC scaffolds will not fork[/]")

    root = pdir / "repo"
    findings, cloned, failed = [], [], []
    repo_paths: dict = {}
    for r in scope["repos"]:
        name = r["url"].rstrip("/").split("/")[-1].removesuffix(".git")
        dest = root / name
        try:
            clone_repo(r["url"], r["branch"], dest)
            cloned.append(dest)
            repo_paths[dest] = r["paths"]
        except CloneError as exc:
            console.print(f"[red]{name}: {exc}[/]")
            failed.append(name)

    prior: list = []
    for dest in cloned:
        prior += find_prior_audits(dest)
    if prior:
        scope["existing_audits"] = prior
        console.print(f"[yellow]{len(prior)} prior audit file(s) in repo - read these first[/]")
        for a in prior[:8]:
            console.print(f"  [dim]{a}[/]")

    all_tools: list = []
    for dest in cloned:
        stats = repo_stats(dest)
        console.print(f"[cyan]auditing[/] {dest.name} ({stats['files']} files)")
        res = run_audit(cfg, dest, RULES_DIR, solidity_mode=True,
                        scope_paths=repo_paths.get(dest) or None)
        console.print(_tool_table(dest.name, res["tools"]))
        all_tools.extend(res["tools"])
        for t_ in res["tools"]:
            db.add_run(pid, t_.get("tool", "?"), t_.get("status", "?"))
        dead = _dead_tools(res["tools"])
        if dead:
            console.print(f"[red]{dest.name}: {', '.join(dead)} failed - tree not compiled[/]")
            failed.append(dest.name)
            continue
        for f in res["findings"]:
            f["file"] = f"{dest.name}/{f.get('file') or ''}"
        findings.extend(res["findings"])

    findings.sort(key=lambda x: -x["cvss"])
    for f in findings:
        db.add_finding(pid, f)

    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        counts[f["severity"]] += 1
    audit = {"findings": findings, "counts": counts, "tools": all_tools}

    for path in write_reports(p, audit, cfg, pdir, {"files": 0, "bytes": 0}, scope):
        console.print(f"[green]report ->[/] {path}")

    if failed:
        console.print(f"\n[red]{len(failed)} of {len(cloned) + len(failed)} repos failed "
                      f"- see the warnings above[/]")

    if cfg.poc.get("enabled", True) and findings:
        fallback = None
        for dest in cloned:
            fallback = first_deployment_address(dest)
            if fallback:
                break
        for path in generate(pdir, findings, scope, fallback,
                             repo=cloned[0] if cloned else None):
            console.print(f"[green]poc ->[/] {path}")

    db.set_status(pid, "error" if not findings else "audited")

    if counts["critical"] or counts["high"]:
        console.print(f"\n[yellow]critical {counts['critical']} / high {counts['high']} "
                      f"- validate against the live target before writing up[/]")

    if not findings:
        sys.exit(1)


def cmd_docs(args):
    cfg, workspace, db, session = _ctx(args)
    res = hunt(cfg, db, session, use_defillama=not args.no_defillama,
               use_gitbook=not args.no_gitbook, use_dorks=not args.no_dorks,
               extra_hosts=args.host or [], limit=args.limit)
    console.print(f"probed {res['hosts_probed']} -> [green]{res['stored']} programs[/]")
    for src, status in res["sources"].items():
        console.print(f"  {src}: {status}")


def cmd_run(args):
    cfg, workspace, db, session = _ctx(args)
    for kw in (args.keyword or cfg.keywords):
        run_discovery(cfg, db, session, kw, use_x=not args.no_x)
    for p in db.list_projects("discovered")[: args.limit]:
        try:
            intel = gather(cfg, session, p, workspace)
            if not intel["repo_url"]:
                db.set_status(p["id"], "no-repo")
                continue
            db.upsert_project(p["platform"], p["slug"], repo_url=intel["repo_url"], status="intel")
            dest = project_dir(workspace, p["platform"], p["slug"]) / "repo" / "src"
            repo = clone_repo(intel["repo_url"], None, dest)
            stats = repo_stats(repo)
            db.upsert_project(p["platform"], p["slug"], local_path=str(repo),
                              stack=detect_stack(repo), status="auditing")
            audit = run_audit(cfg, repo, RULES_DIR, solidity_mode=bool(list(repo.rglob("*.sol"))))
            console.print(_tool_table(repo.name, audit["tools"]))
            dead = _dead_tools(audit["tools"])
            if dead:
                console.print(f"[yellow]{p['slug']}: {', '.join(dead)} failed[/]")
            for f in audit["findings"]:
                db.add_finding(p["id"], f)
            for path in write_reports(db.get_project(p["id"]), audit, cfg,
                                      project_dir(workspace, p["platform"], p["slug"]), stats):
                console.print(f"[green]{p['slug']} ->[/] {path}")
            db.set_status(p["id"], "audited")
        except Exception as exc:
            db.add_run(p["id"], "pipeline", "error", str(exc))
            db.set_status(p["id"], "error")
            console.print(f"[red]{p['slug']}: {exc}[/]")
            if args.verbose:
                traceback.print_exc()
    console.print(f"[green]index ->[/] {write_index(workspace, db)}")


def build_parser():
    ap = argparse.ArgumentParser(prog="bh")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("target", help="intake a bounty URL, then clone + audit")
    p.add_argument("url")
    p.add_argument("--go", action="store_true")
    p.set_defaults(func=cmd_target)

    p = sub.add_parser("discover")
    p.add_argument("-k", "--keyword", action="append")
    p.add_argument("--no-x", action="store_true")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("docs")
    p.add_argument("--host", action="append")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--no-defillama", action="store_true")
    p.add_argument("--no-gitbook", action="store_true")
    p.add_argument("--no-dorks", action="store_true")
    p.set_defaults(func=cmd_docs)

    p = sub.add_parser("links")
    p.add_argument("keyword")
    p.set_defaults(func=cmd_links)

    p = sub.add_parser("rpc", help="verify the configured fork RPC")
    p.set_defaults(func=cmd_rpc)

    p = sub.add_parser("list")
    p.add_argument("--status")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("show")
    p.add_argument("id")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("clone")
    p.add_argument("id")
    p.set_defaults(func=cmd_clone)

    p = sub.add_parser("audit")
    p.add_argument("id")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("attack", help="run fork exploit vectors against a cloned project")
    p.add_argument("id")
    p.add_argument("-V", "--vectors", action="append",
                   help="limit to specific vector names (repeatable)")
    p.set_defaults(func=cmd_attack)

    p = sub.add_parser("run")
    p.add_argument("-k", "--keyword", action="append")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--no-x", action="store_true")
    p.set_defaults(func=cmd_run)
    return ap


def main(argv=None):
    console.print(f"[bold cyan]{BANNER}[/]")
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/]")
        sys.exit(130)