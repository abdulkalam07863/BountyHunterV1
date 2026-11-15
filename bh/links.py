from __future__ import annotations

from urllib.parse import quote_plus

SEARCH_ENGINES = {
    "Google": "https://www.google.com/search?q={q}",
    "Bing": "https://www.bing.com/search?q={q}",
    "DuckDuckGo": "https://duckduckgo.com/?q={q}",
    "Brave": "https://search.brave.com/search?q={q}",
}

TARGETED = {
    "X (live)": "https://x.com/search?q={q}&src=typed_query&f=live",
    "X (top)": "https://x.com/search?q={q}&f=top",
    "GitHub repos": "https://github.com/search?q={q}&type=repositories&s=stars&o=desc",
    "GitHub code": "https://github.com/search?q={q}&type=code",
    "HackerOne hacktivity": "https://hackerone.com/hacktivity?queryString={q}",
    "Bugcrowd": "https://bugcrowd.com/engagements?search={q}",
    "Immunefi": "https://immunefi.com/bug-bounty/?search={q}",
    "security.txt": "https://www.google.com/search?q={q}+%22security.txt%22",
    "NVD": "https://nvd.nist.gov/vuln/search/results?query={q}",
    "Exploit-DB": "https://www.exploit-db.com/search?q={q}",
    "Shodan": "https://www.shodan.io/search?query={q}",
}

X_OPERATORS = [
    ('program', '"{q}" ("bug bounty" OR "bounty program") -filter:replies'),
    ('payouts', '"{q}" ("paid out" OR "bounty awarded")'),
    ('scope', '"{q}" ("in scope" OR "out of scope")'),
]


def for_keyword(keyword: str) -> list:
    q = quote_plus(keyword)
    out = [{"label": f"{n}: {keyword}", "url": t.format(q=q), "kind": "search"}
           for n, t in SEARCH_ENGINES.items()]
    out += [{"label": f"{n}: {keyword}", "url": t.format(q=q), "kind": "platform"}
            for n, t in TARGETED.items()]
    out += [{"label": f"X {n}: {keyword}",
             "url": "https://x.com/search?q=" + quote_plus(t.format(q=keyword)) + "&f=live",
             "kind": "x"} for n, t in X_OPERATORS]
    return out


def for_project(project) -> list:
    name = project["name"] or project["slug"]
    out = for_keyword(name)
    if project["repo_url"]:
        base = project["repo_url"].rstrip("/").removesuffix(".git")
        out += [{"label": l, "url": base + s, "kind": "repo"} for l, s in [
            ("Repo", ""), ("Issues", "/issues"), ("Advisories", "/security/advisories"),
            ("Releases", "/releases"), ("Commits", "/commits"),
            ("Dependencies", "/network/dependencies")]]
    if project["program_url"]:
        out.append({"label": "Program page", "url": project["program_url"], "kind": "program"})
    return out
