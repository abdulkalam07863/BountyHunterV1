"""Hunts self-published bounty policies on docs subdomains."""
from __future__ import annotations

import concurrent.futures as cf
import re
from urllib.parse import unquote, urlparse

from bs4 import BeautifulSoup

from .util import get_json, log, polite_get, short_hash, slugify

STRONG = {"security bounty": 3, "bug bounty program": 3, "bug bounty": 2,
          "vulnerability disclosure policy": 4, "responsible disclosure": 3,
          "safe harbor": 3, "vulnerability disclosure program": 4,
          "security bounty program": 4, "disclosure policy": 2}
MEDIUM = {"in scope": 2, "out of scope": 2, "severity": 2, "critical": 1, "cvss": 2,
          "reward": 2, "triage": 2, "duplicate": 2, "usdc": 1, "bounty": 2,
          "payout": 2, "proof of concept": 1, "hall of fame": 1}
WEAK = {"good faith": 1, "security researcher": 1, "report": 1, "email": 1, "disclose": 1}

SEV_TERMS = ("critical", "high", "medium", "low")
MONEY_RX = re.compile(r"(?:USD|USDC|EUR|GBP|\$)\s?([\d][\d,\.]{1,9})", re.I)
EMAIL_RX = re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]{2,}")
REPO_RX = re.compile(r"https://(?:github|gitlab)\.com/[\w.\-]+/[\w.\-]+")
SCOPE_RX = re.compile(r"`([a-z0-9*][a-z0-9.\-*]{4,})`", re.I)
CVSS_RX = re.compile(r"cvss\s*v?([34])", re.I)

PROBE_PATHS = [
    "security-bounty", "security/bounty", "bug-bounty", "bugbounty", "bounty", "bounties",
    "security-bounty-program", "bug-bounty-program",
    "security-bounty-and-vulnerability-disclosure-policy", "vulnerability-disclosure",
    "vulnerability-disclosure-policy", "responsible-disclosure",
    "security/responsible-disclosure", "security/vulnerability-disclosure",
    "security/bug-bounty", "security/security-bounty", "bounties/security-bounty",
    "bounties/bug-bounty", "security-policy", "security/vdp", "vdp", "security",
    "security/", "security/audits", "audits", "security.txt", ".well-known/security.txt",
    "legal/security", "legal/bounty", "company/security", "trust/security",
    "about/security", "docs/security", "programs/bug-bounty-program",
    "reference/bug-bounty-program",
]

DORKS = ['site:gitbook.io "bug bounty"', 'site:gitbook.io "security bounty"',
         '"security-bounty" inurl:docs', '"bug-bounty" inurl:docs',
         'inurl:docs "security bounty program"',
         'inurl:docs "vulnerability disclosure policy" "scope"',
         '"security bounty" "critical" "cvss" "usdc"',
         '"bug bounty" "out of scope" "safe harbor" docs']

SEED_HOSTS = ["https://docs.aladdin.club", "https://kb.euronodes.com",
              "https://support.gitcoin.co", "https://security.hackclub.com"]

INDEX_PATHS = ("/llms.txt", "/llms-full.txt", "/sitemap.xml", "/sitemap_index.xml")
LOC_RX = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
MDLINK_RX = re.compile(r"\((https?://[^)\s]+)\)")


def _to_int(s: str) -> int:
    try:
        return int(re.sub(r"[,.]", "", s))
    except ValueError:
        return 0


def score(text: str):
    low = text.lower()
    total = 0.0
    for table in (STRONG, MEDIUM, WEAK):
        for term, weight in table.items():
            hits = low.count(term)
            if hits:
                total += weight * min(hits, 3)
    sev_hits = sum(1 for t in SEV_TERMS if t in low)
    if sev_hits >= 3:
        total += 3
    if CVSS_RX.search(text):
        total += 2
    money = MONEY_RX.findall(text)
    if money:
        total += 3
    if EMAIL_RX.search(text):
        total += 2
    meta = {"severity_terms": sev_hits,
            "cvss_version": (CVSS_RX.search(text).group(1) if CVSS_RX.search(text) else None),
            "max_payout": max((_to_int(m) for m in money), default=0),
            "emails": sorted(set(EMAIL_RX.findall(text)))[:5],
            "repos": sorted(set(REPO_RX.findall(text)))[:12],
            "scope_hosts": sorted({h.lower() for h in SCOPE_RX.findall(text)
                                   if "." in h and not h.endswith((".md", ".pdf"))})[:40]}
    return total, meta


def is_program(text: str, min_score: float):
    s, meta = score(text)
    return (s >= min_score and meta["severity_terms"] >= 3
            and (meta["max_payout"] > 0 or meta["emails"])), s, meta


def _fetch(session, url: str, timeout: int = 15):
    try:
        r = polite_get(session, url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None
    if r.status_code != 200:
        return None
    ct = r.headers.get("content-type", "").lower()
    if "text" not in ct and "json" not in ct:
        return None
    if len(r.content) > 1_500_000:
        return None
    return r


def _plain(r) -> str:
    if "html" in r.headers.get("content-type", "").lower():
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        return soup.get_text(" ", strip=True)
    return r.text


def _index_urls(session, base: str):
    found, host = [], urlparse(base).netloc
    for path in INDEX_PATHS:
        r = _fetch(session, base.rstrip("/") + path)
        if not r:
            continue
        for u in LOC_RX.findall(r.text) + MDLINK_RX.findall(r.text):
            if urlparse(u).netloc != host:
                continue
            if any(k in urlparse(u).path.lower() for k in ("bount", "disclos", "vdp", "security-policy")):
                found.append(u)
        if found:
            break
    return list(dict.fromkeys(found))


def _probe_paths(session, base: str, paths):
    hits = []
    for p in paths:
        r = _fetch(session, base.rstrip("/") + "/" + p.lstrip("/"), timeout=12)
        if not r:
            continue
        if any(k in _plain(r).lower() for k in ("bounty", "disclosure", "vulnerability")):
            hits.append(base.rstrip("/") + "/" + p.lstrip("/"))
    return hits


def probe_host(session, base: str, cfg) -> list:
    out = []
    cands = _index_urls(session, base)
    used_index = bool(cands)
    if not cands:
        cands = _probe_paths(session, base, cfg.docs.get("probe_paths") or PROBE_PATHS)
    min_score = float(cfg.docs.get("min_score", 8))
    for url in cands[:12]:
        r = _fetch(session, url)
        if not r:
            continue
        text = _plain(r)
        if len(text) < 400:
            continue
        ok, s, meta = is_program(text, min_score)
        if not ok:
            continue
        host = urlparse(base).netloc
        out.append({"platform": "docs",
                    "slug": slugify(host + "-" + urlparse(url).path.strip("/").replace("/", "-"))[:70],
                    "name": host + urlparse(url).path, "program_url": url,
                    "repo_url": meta["repos"][0] if meta["repos"] else None,
                    "payout": f"up to {meta['max_payout']:,}" if meta["max_payout"] else None,
                    "scope": ", ".join(meta["scope_hosts"][:10]) or None,
                    "description": f"score={s:.0f}; contact={','.join(meta['emails']) or '-'}",
                    "source_id": short_hash(url), "confidence": min(1.0, s / 25),
                    "extra_repos": meta["repos"], "indexed": used_index})
    return out


def hosts_from_defillama(session, limit: int = 300):
    data, err = get_json(session, "https://api.llama.fi/protocols")
    if err or not isinstance(data, list):
        return [], f"error: {err}"
    data.sort(key=lambda p: p.get("tvl") or 0, reverse=True)
    hosts = []
    for p in data[:limit]:
        url = (p.get("url") or "").strip()
        if not url:
            continue
        netloc = urlparse(url if "://" in url else "https://" + url).netloc
        if not netloc:
            continue
        root = ".".join(netloc.split(".")[-2:])
        hosts += [f"https://docs.{netloc}", f"https://kb.{netloc}",
                  f"https://{netloc}/docs", f"https://{netloc}/security",
                  f"https://{root}/security"]
    return list(dict.fromkeys(hosts)), "ok"


def hosts_from_gitbook(session, max_pages: int = 4):
    hosts = []
    for q in ['site:gitbook.io "bug bounty"', 'site:gitbook.io "security bounty"']:
        for page in range(max_pages):
            try:
                r = polite_get(session, "https://html.duckduckgo.com/html/?q="
                               + q.replace(" ", "+") + (f"&s={page * 30}" if page else ""),
                               timeout=25)
            except Exception:
                break
            if r.status_code != 200:
                break
            added = 0
            for a in BeautifulSoup(r.text, "html.parser").select("a.result__a"):
                m = re.search(r"https://([\w\-]+\.gitbook\.io)", a.get("href", ""))
                if m:
                    hosts.append("https://" + m.group(1))
                    added += 1
            if not added:
                break
    return list(dict.fromkeys(hosts)), "ok" if hosts else "empty"


def hosts_from_search(session, dorks, max_pages: int = 3):
    urls = []
    for dork in dorks:
        for page in range(max_pages):
            try:
                r = polite_get(session, "https://html.duckduckgo.com/html/?q="
                               + dork.replace(" ", "+") + (f"&s={page * 30}" if page else ""),
                               timeout=25)
            except Exception:
                break
            if r.status_code != 200:
                break
            added = 0
            for a in BeautifulSoup(r.text, "html.parser").select("a.result__a"):
                href = a.get("href", "")
                m = re.search(r"uddg=([^&]+)", href)
                if m:
                    href = unquote(m.group(1))
                if href.startswith("http") and any(k in href.lower() for k in ("bount", "disclos")):
                    urls.append(href)
                    added += 1
            if not added:
                break
        try:
            r = polite_get(session, "https://www.mojeek.com/search?q=" + dork.replace(" ", "+"),
                           timeout=25)
            if r.status_code == 200:
                for a in BeautifulSoup(r.text, "html.parser").select("a.ob"):
                    href = a.get("href", "")
                    if href.startswith("http") and any(k in href.lower() for k in ("bount", "disclos")):
                        urls.append(href)
        except Exception:
            pass
    return list(dict.fromkeys(urls)), "ok" if urls else "empty"


def hunt(cfg, db, session, *, use_defillama, use_gitbook, use_dorks, extra_hosts, limit) -> dict:
    report, hosts = {}, list(extra_hosts) + list(cfg.docs.get("seed_hosts") or SEED_HOSTS)
    tasks = []
    with cf.ThreadPoolExecutor(max_workers=max(1, cfg.max_concurrency)) as pool:
        if use_defillama:
            tasks.append((pool.submit(hosts_from_defillama, session, limit), "defillama"))
        if use_gitbook:
            tasks.append((pool.submit(hosts_from_gitbook, session), "gitbook-search"))
        if use_dorks:
            tasks.append((pool.submit(hosts_from_search, session, DORKS), "dorks"))
        for fut, name in tasks:
            try:
                found, status = fut.result()
            except Exception as exc:
                report[name] = f"crash: {exc}"
                continue
            report[name] = f"{status} ({len(found)})"
            hosts += [f"https://{urlparse(u).netloc}" for u in found] if name == "dorks" else found

    hosts = list(dict.fromkeys(h.strip().rstrip("/") for h in hosts if h.strip()))[: limit * 3]
    stored, seen = 0, set()
    with cf.ThreadPoolExecutor(max_workers=max(1, cfg.max_concurrency)) as pool:
        futures = {pool.submit(probe_host, session, h, cfg): h for h in hosts}
        for fut in cf.as_completed(futures):
            try:
                records = fut.result()
            except Exception:
                continue
            for rec in records:
                if rec["slug"] in seen:
                    continue
                seen.add(rec["slug"])
                pid = db.upsert_project(rec["platform"], rec["slug"], name=rec["name"],
                                        program_url=rec["program_url"], repo_url=rec["repo_url"],
                                        payout=rec["payout"], scope=rec["scope"],
                                        description=rec["description"], status="verified")
                for extra in rec["extra_repos"][:6]:
                    db.add_link(pid, "repo in scope", extra, "repo")
                stored += 1
                log.info("HIT %s", rec["program_url"])
    return {"sources": report, "hosts_probed": len(hosts), "stored": stored}
