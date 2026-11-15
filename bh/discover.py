from __future__ import annotations

import concurrent.futures as cf

from . import links, sources
from .util import log


def run_discovery(cfg, db, session, keyword: str, use_x: bool = True) -> dict:
    report: dict = {}
    records: list = []

    for link in links.for_keyword(keyword):
        db.add_link(None, link["label"], link["url"], link["kind"])

    jobs = {}
    with cf.ThreadPoolExecutor(max_workers=cfg.max_concurrency) as pool:
        for name, fn in sources.FETCHERS.items():
            if cfg.platforms.get(name):
                jobs[pool.submit(fn, session, cfg.pages_per_source)] = name
        if cfg.platforms.get("github"):
            jobs[pool.submit(sources.github, session, keyword)] = "github"
        if cfg.platforms.get("x") and use_x:
            jobs[pool.submit(sources.x_search, session, keyword,
                             cfg.cred("x", "bearer_token_env"))] = "x"
        for fut in cf.as_completed(jobs):
            name = jobs[fut]
            try:
                recs, status = fut.result()
            except Exception as exc:
                report[name] = f"crash: {exc}"
                continue
            report[name] = status
            records.extend(recs)
            log.info("[%s] %s (%d)", keyword, status, len(recs))

    for rec in records:
        pid = db.upsert_project(rec["platform"], rec["slug"], name=rec.get("name"),
                                program_url=rec.get("program_url"), repo_url=rec.get("repo_url"),
                                scope=rec.get("scope"), payout=rec.get("payout"),
                                description=rec.get("description"))
        for link in links.for_project(rec):
            db.add_link(pid, link["label"], link["url"], link["kind"])

    return {"keyword": keyword, "sources": report, "stored": len(records)}
