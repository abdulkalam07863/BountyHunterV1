from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .util import human_bytes, redact

SEV_COLOR = {"critical": "#8e1b1b", "high": "#c0392b", "medium": "#d68910",
             "low": "#2471a3", "info": "#5d6d7e"}

MANUAL = """\
## Manual testing checklist

**Authentication** - reset token entropy/reuse, MFA bypass, session fixation, OAuth state/PKCE.
**Authorisation** - IDOR across every object id, vertical escalation, mass assignment, cross-tenant reads.
**Injection** - every SQL search/sort param, SSRF on URL-fetch features, SSTI in email/report rendering,
command injection in export pipelines, XXE on XML/SAML import.
**Business logic** - negative quantities, coupon stacking, race on redeem, proration abuse, upload mismatch.
**Client side** - stored XSS in fields rendered elsewhere, postMessage origin checks, CORS with credentials.
**Infrastructure** - cloud metadata reachability, subdomain takeover, /actuator, /.git/config.
"""

DEFI_MANUAL = """\
## DeFi-specific manual checklist

**Oracle** - flash-loan the spot source and check the TWAP window holds; push a stale feed and confirm
borrow limits move; test decimals mismatch on every feed.
**Accounting** - deposit 1 wei first then donate to inflate share price; withdraw to the last wei and
confirm rounding favours the protocol; check fee-on-transfer and rebasing assets end to end.
**Liquidation** - liquidate at exactly the threshold, in the same block as a price update.
**Reentrancy** - ERC777/ERC721/ERC1155 callback tokens and any receive() path that re-enters.
**Upgrade** - storage layout diff between implementation versions; re-initialisation on a fresh proxy;
facet selector collisions in the diamond.
**Economic** - required capital, attacker profit, gas, recoverability.
"""


def _snippet(text, max_lines: int = 12):
    return "\n".join((text or "").splitlines()[:max_lines])


def build_markdown(project, audit, cfg, workspace: Path, stats: dict, scope=None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts, total = audit["counts"], len(audit["findings"])
    L = [f"# Security Audit - {project['name'] or project['slug']}\n", "| Field | Value |\n|---|---|"]
    L += [f"| Project ID | {project['id']} |", f"| Platform | {project['platform']} |",
          f"| Program | {project['program_url'] or '-'} |",
          f"| Repository | {project['repo_url'] or '-'} |",
          f"| Stack | {project['stack'] or 'unknown'} |",
          f"| Payout range | {project['payout'] or '-'} |",
          f"| Generated | {now} |",
          f"| Files scanned | {stats.get('files', 0)} ({human_bytes(stats.get('bytes', 0))}) |", ""]

    if scope:
        L.append("## Program scope\n")
        for r in scope.get("repos", []):
            L.append(f"- `{r['url']}` - {', '.join(r['paths']) or 'whole repository'}")
        if scope.get("severity_table"):
            L.append("\n| Severity | CVSS | Max reward |\n|---|---|---|")
            L += [f"| {s['severity']} | {s['cvss']} | ${s['max_reward']:,} |"
                  for s in scope["severity_table"]]
        if scope.get("contacts"):
            L.append(f"\nReporting: {', '.join(scope['contacts'])}")
        if scope.get("existing_audits"):
            L.append("\n**Read before reporting - existing audits:**\n")
            L += [f"- {a}" for a in scope["existing_audits"][:20]]
        if scope.get("exclusions"):
            L.append("\n**Stated exclusions:**\n")
            L += [f"- {e}" for e in scope["exclusions"][:15]]
        L.append("")

    L += ["## Executive summary\n", f"**{total}** findings after deduplication, scope filter and per-rule cap.\n",
          "| Severity | Count |\n|---|---|"]
    L += [f"| {s.capitalize()} | {counts.get(s, 0)} |" for s in ("critical", "high", "medium", "low", "info")]
    L.append("")

    L.append("## Tool coverage\n")
    L.append("| Tool | Status |\n|---|---|")
    L += [f"| {t.get('tool')} | {t.get('status')} |" for t in audit["tools"]]
    L.append("")

    L.append("## Findings\n")
    if not audit["findings"]:
        L.append("_No findings at or above the floor._\n")
    for f in audit["findings"]:
        L += [f"### [{f['fid']}] {f['title']}\n", "| | |\n|---|---|",
              f"| Severity | **{f['severity'].upper()}** (CVSS~{f['cvss']}) |",
              f"| Confidence | {f['confidence']} |", f"| Category | {f['category']} |"]
        if f.get("cwe"):
            L.append(f"| CWE | [{f['cwe']}](https://cwe.mitre.org/data/definitions/{f['cwe'].split('-')[-1]}.html) |")
        L.append(f"| Location | `{f.get('file') or '-'}`" + (f":{f['line']}" if f.get("line") else "") + " |")
        L.append(f"| Detector | {f.get('tool')} |\n")
        if f.get("detail"):
            L.append(f"{f['detail']}\n")
        if f.get("code") and cfg.report.get("include_code_snippets", True):
            snip = _snippet(f["code"])
            if cfg.report.get("redact_secrets", True) and f.get("category") == "secret":
                snip = "\n".join(redact(x, 4) if len(x) > 40 else x for x in snip.splitlines())
            L.append("```\n" + snip + "\n```\n")
        if f.get("remediation"):
            L.append(f"**Remediation.** {f['remediation']}\n")
        refs = f.get("references") or []
        if isinstance(refs, str):
            try:
                refs = json.loads(refs)
            except json.JSONDecodeError:
                refs = []
        if refs:
            L.append("**References.** " + " . ".join(f"<{r}>" for r in refs[:6]) + "\n")
        L.append("---\n")

    L.append(DEFI_MANUAL if project["platform"] == "target" else MANUAL)
    L += ["## Appendix - scan log\n", "```"]
    L += [f"{t.get('tool'):<14} {t.get('status')}" for t in audit["tools"]]
    L += ["```", f"\nArtifacts: `{workspace}`"]
    return "\n".join(L)


def build_html(project, audit, cfg, workspace: Path, stats: dict, scope=None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = "".join(
        f'<details style="border-left:4px solid {SEV_COLOR[f["severity"]]}">'
        f'<summary><span class="badge" style="background:{SEV_COLOR[f["severity"]]}">'
        f'{f["severity"].upper()}</span> <code>{f["fid"]}</code> {f["title"]}</summary>'
        f'<p class="meta">CVSS~{f["cvss"]} - {f["category"]} - {f.get("tool")}</p>'
        f'<p>{f.get("detail") or ""}</p>'
        + (f'<pre>{_snippet(f.get("code"))}</pre>' if f.get("code") else "")
        + f'<p><b>Remediation.</b> {f.get("remediation") or "-"}</p></details>'
        for f in audit["findings"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Audit - {project['name'] or project['slug']}</title><style>
:root{{color-scheme:dark}}body{{font:15px/1.6 ui-sans-serif,system-ui,sans-serif;background:#0f1115;
color:#d7dae0;max-width:1100px;margin:auto;padding:32px}}
details{{background:#151821;border-radius:6px;margin:9px 0;padding:10px 14px}}
summary{{cursor:pointer;font-weight:600}}.badge{{color:#fff;padding:1px 7px;border-radius:3px;font-size:11px}}
pre{{background:#0b0d12;padding:11px;border-radius:5px;overflow-x:auto;font-size:12px}}
.meta{{color:#7b8290;font-size:12px}}
</style></head><body><h1>Security Audit - {project['name'] or project['slug']}</h1>
<p class="meta">{project['platform']} - {now} - {len(audit['findings'])} findings</p>
<p>{project['program_url'] or ''}</p>{rows}</body></html>"""


def write_reports(project, audit, cfg, project_path: Path, stats: dict, scope=None) -> list:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = project_path / "reports" / f"audit-{ts}"
    written = []
    payload = {"project": dict(project), "scope": scope, "counts": audit["counts"],
               "tools": audit["tools"], "findings": audit["findings"],
               "generated": datetime.now(timezone.utc).isoformat()}
    for fmt in cfg.report.get("formats", ["md", "json"]):
        if fmt == "md":
            p = base.with_suffix(".md")
            p.write_text(build_markdown(project, audit, cfg, project_path, stats, scope), encoding="utf-8")
        elif fmt == "json":
            p = base.with_suffix(".json")
            p.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        elif fmt == "html":
            p = base.with_suffix(".html")
            p.write_text(build_html(project, audit, cfg, project_path, stats, scope), encoding="utf-8")
        else:
            continue
        written.append(p)
    return written


def write_index(workspace: Path, db) -> Path:
    projects = db.list_projects()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# Bounty portfolio\n\nGenerated {now} - {len(projects)} projects\n",
             "| ID | Platform | Name | Repo | Status |", "|---|---|---|---|---|"]
    lines += [f"| {p['id']} | {p['platform']} | {(p['name'] or p['slug'])[:60]} | "
              f"{p['repo_url'] or '-'} | {p['status']} |" for p in projects]
    out = workspace / "INDEX.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out
