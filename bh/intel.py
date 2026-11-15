from __future__ import annotations

import re
from pathlib import Path

from .util import polite_get

MANIFESTS = {"package.json": "node", "requirements.txt": "python", "pyproject.toml": "python",
             "go.mod": "go", "Cargo.toml": "rust", "Gemfile": "ruby", "composer.json": "php",
             "pom.xml": "java", "build.gradle": "java", "Dockerfile": "docker",
             "foundry.toml": "solidity", "hardhat.config.js": "solidity",
             "hardhat.config.ts": "solidity", "truffle-config.js": "solidity"}

SECURITY_TXT = ("/.well-known/security.txt", "/security.txt")


def detect_stack(repo: Path) -> str:
    return ", ".join(sorted({lang for name, lang in MANIFESTS.items()
                             if (repo / name).exists()})) or "unknown"


def normalise_repo(url):
    if not url:
        return None
    url = url.strip()
    if url.endswith(".git"):
        return url
    if re.match(r"^https?://(github|gitlab|bitbucket)\.(com|org)/[\w.\-]+/[\w.\-]+/?$", url):
        return url.rstrip("/") + ".git"
    return url


def fetch_security_txt(session, base_url):
    if not base_url:
        return None
    for path in SECURITY_TXT:
        try:
            r = polite_get(session, base_url.rstrip("/") + path)
            if r.status_code == 200 and "contact" in r.text.lower():
                return r.text[:4000]
        except Exception:
            continue
    return None


def gather(cfg, session, project, workspace) -> dict:
    notes, repo_url = [], normalise_repo(project["repo_url"])
    if not repo_url and project["program_url"]:
        try:
            r = polite_get(session, project["program_url"])
            if r.status_code == 200:
                m = re.search(r"https://github\.com/[\w.\-]+/[\w.\-]+", r.text)
                if m:
                    repo_url = normalise_repo(m.group(0))
                    notes.append("repo discovered on program page")
        except Exception as exc:
            notes.append(f"page fetch failed: {exc}")
    sec = fetch_security_txt(session, project["program_url"])
    if sec:
        notes.append("security.txt found")
    return {"repo_url": repo_url, "security_txt": sec, "notes": notes}


def find_prior_audits(repo: Path) -> list:
    """Local audit PDFs/markdown already in the repo."""
    out = []
    for d in ("audit-reports", "audits", "audit", "docs/audits", "security/audits"):
        folder = repo / d
        if folder.is_dir():
            out += [str(p.relative_to(repo)) for p in sorted(folder.iterdir()) if p.is_file()]
    return out[:40]


def first_deployment_address(repo: Path) -> str | None:
    """Pull an address out of deployments/*.json for PoC scaffolding."""
    import json
    for path in list(repo.glob("deployments/*.json"))[:12]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text) > 400_000:
            continue
        for key in ("address", "proxy", "implementation", "concentrator", "clever"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                break
            if isinstance(data, dict):
                for k, v in data.items():
                    if key in k.lower() and isinstance(v, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", v):
                        return v
        m = re.search(r"0x[0-9a-fA-F]{40}", text)
        if m:
            return m.group(0)
    return None
