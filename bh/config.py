from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Config:
    workspace_root: str = r"D:\BugBounty"
    fallback_root: str = r"C:\BugBounty"
    max_concurrency: int = 6
    request_timeout: int = 25
    rate_limit_rps: float = 1.5
    user_agent: str = "bountyhunter/1.1"
    keywords: list = field(default_factory=list)
    platforms: dict = field(default_factory=dict)
    pages_per_source: int = 3
    clone: dict = field(default_factory=dict)
    audit: dict = field(default_factory=dict)
    report: dict = field(default_factory=dict)
    docs: dict = field(default_factory=dict)
    solidity: dict = field(default_factory=dict)
    poc: dict = field(default_factory=dict)
    creds: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path = "config.yaml") -> "Config":
        p = Path(path)
        raw = {}
        if p.exists():
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        c = cls()
        for k, v in raw.items():
            if k in ("hackerone", "intigriti", "x"):
                c.creds[k] = v or {}
                continue
            if hasattr(c, k):
                setattr(c, k, v)
        if not c.keywords:
            c.keywords = ["bug bounty program", "responsible disclosure"]
        if not c.platforms:
            c.platforms = {"hackerone": True, "bugcrowd": True, "yeswehack": True,
                           "immunefi": True, "intigriti": True, "github": True, "x": True}
        for d in ("audit", "report", "clone", "docs", "solidity", "poc"):
            if not isinstance(getattr(c, d), dict):
                setattr(c, d, {})
        return c

    def cred(self, group: str, key: str):
        env_name = (self.creds.get(group) or {}).get(key)
        return os.environ.get(env_name) if env_name else None
