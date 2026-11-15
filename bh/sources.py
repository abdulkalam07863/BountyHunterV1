from __future__ import annotations

import re
from urllib.parse import quote_plus

from bs4 import BeautifulSoup

from .util import get_json, polite_get, short_hash, slugify


def _rec(platform, name, url, **kw):
    return {"platform": platform, "slug": kw.pop("slug", None) or slugify(name),
            "name": name.strip(), "program_url": url, "repo_url": kw.get("repo_url"),
            "payout": kw.get("payout"), "scope": kw.get("scope"),
            "description": kw.get("description"), "source_id": short_hash(url or name)}


def bugcrowd(session, pages: int):
    out, errs = [], []
    for page in range(1, pages + 1):
        data, err = get_json(session, "https://bugcrowd.com/engagements.json"
                             f"?category=bug_bounty&sort_by=promoted&page={page}")
        if err:
            errs.append(f"p{page}: {err}")
            break
        items = data.get("engagements") or data.get("data") or []
        if not items:
            break
        for it in items:
            name = it.get("name") or it.get("brief")
            if not name:
                continue
            path = it.get("briefUrl") or ""
            out.append(_rec("bugcrowd", name,
                            "https://bugcrowd.com" + path if path.startswith("/") else path,
                            payout=it.get("rewardRange"),
                            description=(it.get("description") or "")[:600]))
    return out, ("ok" if out else "empty" if not errs else "error: " + "; ".join(errs[:3]))


def yeswehack(session, pages: int):
    out, errs = [], []
    for page in range(1, pages + 1):
        data, err = get_json(session, f"https://api.yeswehack.com/programs?page={page}")
        if err:
            errs.append(f"p{page}: {err}")
            break
        items = data.get("items") or []
        if not items:
            break
        for it in items:
            title = it.get("title") or it.get("name")
            if not title:
                continue
            slug = it.get("slug") or slugify(title)
            out.append(_rec("yeswehack", title, f"https://yeswehack.com/programs/{slug}",
                            slug=slug, payout=str(it.get("reward_max") or "")))
    return out, ("ok" if out else "empty" if not errs else "error: " + "; ".join(errs[:3]))


def immunefi(session, pages: int):
    out = []
    data, err = get_json(session, "https://immunefi.com/public-api/bounties")
    if err:
        return out, f"error: {err}"
    items = data if isinstance(data, list) else (data.get("bounties") or [])
    for it in items:
        name = it.get("project") or it.get("name")
        if not name:
            continue
        pid = it.get("id") or slugify(name)
        out.append(_rec("immunefi", name, f"https://immunefi.com/bounty/{pid}/",
                        payout=str(it.get("maximumReward") or ""),
                        description=(it.get("shortDescription") or "")[:600]))
    return out, ("ok" if out else "empty")


def hackerone(session, pages: int):
    out, errs = [], []
    for page in range(1, pages + 1):
        try:
            r = polite_get(session, f"https://hackerone.com/directory/programs?page={page}")
        except Exception as exc:
            errs.append(str(exc))
            break
        if r.status_code != 200:
            errs.append(f"HTTP {r.status_code}")
            break
        soup = BeautifulSoup(r.text, "html.parser")
        found = 0
        for a in soup.select('a[href^="/"]'):
            href = a.get("href", "")
            if not re.match(r"^/[A-Za-z0-9_.\-]+$", href):
                continue
            name = a.get_text(" ", strip=True)
            if len(name) < 3:
                continue
            out.append(_rec("hackerone", name, "https://hackerone.com" + href))
            found += 1
        if not found:
            break
    seen, uniq = set(), []
    for r_ in out:
        if r_["slug"] not in seen:
            seen.add(r_["slug"])
            uniq.append(r_)
    return uniq, ("ok" if uniq else "empty" if not errs else "error: " + "; ".join(errs[:3]))


def intigriti(session, pages: int):
    out, errs = [], []
    for page in range(1, pages + 1):
        try:
            r = polite_get(session, f"https://www.intigriti.com/researcher/programs?page={page}")
        except Exception as exc:
            errs.append(str(exc))
            break
        if r.status_code != 200:
            errs.append(f"HTTP {r.status_code}")
            break
        soup = BeautifulSoup(r.text, "html.parser")
        found = 0
        for a in soup.select('a[href*="/researcher/programs/"]'):
            name = a.get_text(" ", strip=True)
            if not name:
                continue
            href = a.get("href", "")
            out.append(_rec("intigriti", name,
                            href if href.startswith("http") else "https://www.intigriti.com" + href))
            found += 1
        if not found:
            break
    return out, ("ok" if out else "empty" if not errs else "error: " + "; ".join(errs[:3]))


def github(session, keyword: str, limit: int = 15):
    out = []
    data, e = get_json(session, "https://api.github.com/search/repositories?q="
                       + quote_plus(keyword) + "&sort=stars&order=desc&per_page=" + str(limit),
                       headers={"Accept": "application/vnd.github+json"})
    if e:
        return out, f"error: {e}"
    for it in (data or {}).get("items", [])[:limit]:
        if not it.get("full_name"):
            continue
        out.append(_rec("github", it["full_name"], it.get("html_url"),
                        repo_url=it.get("clone_url"),
                        description=(it.get("description") or "")[:400]))
    return out, ("ok" if out else "empty")


def x_search(session, keyword: str, bearer, limit: int = 25):
    if not bearer:
        return [], "skipped: no bearer token"
    try:
        r = polite_get(session, "https://api.x.com/2/tweets/search/recent?query="
                       + quote_plus(f'"{keyword}" ("bug bounty" OR bounty) -filter:replies')
                       + f"&max_results={max(10, min(limit, 100))}&tweet.fields=entities",
                       headers={"Authorization": f"Bearer {bearer}"})
    except Exception as exc:
        return [], f"error: {exc}"
    if r.status_code != 200:
        return [], f"HTTP {r.status_code}"
    out = []
    for tw in (r.json() or {}).get("data", []):
        urls = [u.get("expanded_url") for u in
                (tw.get("entities", {}) or {}).get("urls", []) if u.get("expanded_url")]
        out.append({"platform": "x", "slug": "x-" + short_hash(tw.get("id", "")),
                    "name": (tw.get("text") or "")[:110].replace("\n", " "),
                    "program_url": f"https://x.com/i/web/status/{tw.get('id')}",
                    "repo_url": next((u for u in urls if "github.com" in u), None),
                    "payout": None, "scope": None, "description": tw.get("text"),
                    "source_id": short_hash(tw.get("id", ""))})
    return out, ("ok" if out else "empty")


FETCHERS = {"hackerone": hackerone, "bugcrowd": bugcrowd, "yeswehack": yeswehack,
            "immunefi": immunefi, "intigriti": intigriti}
