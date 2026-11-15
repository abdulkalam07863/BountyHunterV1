"""Single-URL intake: bounty page -> machine-readable scope file."""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

from bs4 import BeautifulSoup

from .util import log, polite_get, slugify

REPO_RX = re.compile(r"https://(?:github|gitlab)\.com/([\w.\-]+)/([\w.\-]+)"
                     r"(?:/(?:tree|blob)/([^/\s)\]\"'>]+)(/[^\s)\]\"'>]*)?)?", re.I)
EMAIL_RX = re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]{2,}")
SEV_ROW_RX = re.compile(r"\|\s*(critical|high|medium|low|informational)\s*\|\s*"
                        r"([\d.]+\s*[-\u2013]\s*[\d.]+|n/?a)?\s*\|\s*(?:USD|USDC|\$|EUR)\s*([\d,]+)", re.I)
CHAIN_RX = re.compile(r"\b(ethereum|mainnet|arbitrum|optimism|base|polygon|bsc|avalanche|"
                      r"berachain|sonic|blast|linea|scroll)\b", re.I)
ADDR_RX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
AUDIT_RX = re.compile(r"https?://[^\s)\]\"'>]+(?:audit|Audit)[^\s)\]\"'>]*\.pdf", re.I)


def _text(url: str, session):
    for i, u in enumerate([url.rstrip("/") + ".md", url]):
        try:
            r = polite_get(session, u, timeout=25)
        except Exception as exc:
            log.debug("fetch %s: %s", u, exc)
            continue
        if r.status_code != 200:
            continue
        if "html" in r.headers.get("content-type", "") and i == 1:
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup(["script", "style", "nav", "footer"]):
                tag.decompose()
            return soup.get_text("\n", strip=True), u
        return r.text, u
    raise RuntimeError(f"could not fetch {url}")


def parse_scope(page_url: str, text: str) -> dict:
    repos: dict = {}
    for m in REPO_RX.finditer(text):
        key = f"{m.group(1)}/{m.group(2)}"
        entry = repos.setdefault(key, {"url": f"https://github.com/{key}.git",
                                       "branch": None, "paths": []})
        if m.group(3):
            entry["branch"] = unquote(m.group(3))
            if m.group(4):
                entry["paths"].append(unquote(m.group(4).strip("/")))

    sev = [{"severity": m.group(1).lower(), "cvss": (m.group(2) or "").replace(" ", ""),
            "max_reward": int(m.group(3).replace(",", ""))} for m in SEV_ROW_RX.finditer(text)]

    exclusions = []
    for line in text.splitlines():
        s = line.strip(" *-\t")
        if len(s) > 12 and re.search(r"\b(out of scope|not eligible|not rewarded|"
                                     r"not independently|deprecated|excluded)\b", s, re.I):
            exclusions.append(s[:220])

    return {"source_url": page_url, "title": (text.splitlines()[0] if text else "")[:160],
            "repos": list(repos.values()), "severity_table": sev,
            "contacts": sorted(set(EMAIL_RX.findall(text)))[:6],
            "chains": sorted({c.lower() for c in CHAIN_RX.findall(text)}),
            "addresses": sorted(set(ADDR_RX.findall(text)))[:40],
            "existing_audits": sorted(set(AUDIT_RX.findall(text)))[:30],
            "exclusions": exclusions[:25],
            "cvss_version": (re.search(r"cvss\s*v?([34])", text, re.I) or [None, None])[1],
            "requires_poc": bool(re.search(r"proof of concept|poc|reproduc", text, re.I)),
            "email_only": not bool(re.search(r"hackerone|bugcrowd|immunefi|intigriti", text, re.I))}


def intake(cfg, db, session, url: str):
    text, used = _text(url, session)
    scope = parse_scope(url, text)
    if not scope["repos"]:
        raise RuntimeError("no repository in scope - page may be JS-rendered")
    host = urlparse(url).netloc
    pid = db.upsert_project(
        "target", slugify(host + "-" + urlparse(url).path.strip("/").replace("/", "-")),
        name=scope["title"] or host, program_url=url, repo_url=scope["repos"][0]["url"],
        payout=(f"critical {max(s['max_reward'] for s in scope['severity_table']):,}"
                if scope["severity_table"] else None),
        scope=", ".join(f"{r['url'].split('/')[-1]}:{','.join(r['paths']) or '*'}"
                        for r in scope["repos"])[:1500],
        description=f"chains={','.join(scope['chains'])}; contacts={','.join(scope['contacts'])}; "
                    f"cvss_v={scope['cvss_version']}; audits={len(scope['existing_audits'])}",
        status="scoped")
    for e in scope["contacts"]:
        db.add_link(pid, f"contact {e}", f"mailto:{e}", "contact")
    for a in scope["existing_audits"]:
        db.add_link(pid, "existing audit", a, "audit")
    db.add_run(pid, "intake", "ok", f"parsed via {used}")
    return pid, scope


def save_scope(project_path: Path, scope: dict) -> Path:
    p = project_path / "scope.json"
    p.write_text(json.dumps(scope, indent=2), encoding="utf-8")
    return p
