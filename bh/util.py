from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("bh")

BANNER = r"""
 | |__   ___  _   _ _ __ | |_| |__  _   _ _ __ | |_ ___ _ __
 | '_ \ / _ \| | | | '_ \| __| '_ \| | | | '_ \| __/ _ \ '__|
 | |_) | (_) | |_| | | | | |_| | | | |_| | | | | ||  __/ |
 |_.__/ \___/ \__,_|_| |_|\__|_| |_|\__,_|_| |_|_|\___|_|
"""


def slugify(text: str, maxlen: int = 60) -> str:
    text = unicodedata.normalize("NFKD", str(text))
    text = re.sub(r"[^\w\s.\-]", "", text, flags=re.UNICODE)
    text = re.sub(r"[\s_]+", "-", text).strip("-.")
    return (text[:maxlen] or "project").lower()


def short_hash(text: str, n: int = 8) -> str:
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:n]


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def redact(value: str, keep: int = 6) -> str:
    if not value:
        return ""
    value = value.strip()
    if len(value) <= keep * 2:
        return value[:2] + "*" * max(len(value) - 2, 0)
    return value[:keep] + "*" * 8 + value[-keep:]


def resolve_workspace(cfg) -> Path:
    for candidate in (cfg.workspace_root, cfg.fallback_root):
        p = Path(candidate)
        try:
            if not p.exists():
                drive = p.drive
                if drive and not Path(drive + "\\").exists():
                    continue
                p.mkdir(parents=True, exist_ok=True)
            if p.is_dir() and os.access(p, os.W_OK):
                return p
        except OSError:
            continue
    p = Path.cwd() / "BugBounty"
    p.mkdir(parents=True, exist_ok=True)
    log.warning("workspace_root unavailable, using %s", p)
    return p


def project_dir(workspace: Path, platform: str, slug: str) -> Path:
    d = workspace / slugify(platform) / slug
    for sub in ("repo", "reports", "evidence", "logs", "poc"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    return d


def repo_stats(repo: Path) -> dict:
    files = [f for f in repo.rglob("*") if f.is_file() and ".git" not in f.parts]
    return {"files": len(files),
            "bytes": sum(f.stat().st_size for f in files),
            "extensions": len({f.suffix.lower() for f in files if f.suffix})}


def make_session(rps: float = 1.5, timeout: int = 25, ua: str = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": ua or "bountyhunter/1.1",
        "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    retry = Retry(total=3, backoff_factor=0.7, read=3, connect=3,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset({"GET", "POST"}),
                  respect_retry_after_header=True)
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s._bh_min_interval = 1.0 / max(rps, 0.05)
    s._bh_last = 0.0
    s._bh_timeout = timeout
    return s


def polite_get(session, url: str, **kw):
    gap = session._bh_min_interval - (time.time() - session._bh_last)
    if gap > 0:
        time.sleep(gap)
    kw.setdefault("timeout", session._bh_timeout)
    r = session.get(url, **kw)
    session._bh_last = time.time()
    return r


def polite_post(session, url: str, **kw):
    gap = session._bh_min_interval - (time.time() - session._bh_last)
    if gap > 0:
        time.sleep(gap)
    kw.setdefault("timeout", session._bh_timeout)
    r = session.post(url, **kw)
    session._bh_last = time.time()
    return r


def get_json(session, url, **kw):
    try:
        r = polite_get(session, url, **kw)
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        return r.json(), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def have_tool(name: str) -> bool:
    return shutil.which(name) is not None


def resolve_rpc(cfg) -> str:
    """Single source of truth for the fork RPC.

    Config names the variable; the value comes from the environment (.env or
    shell). Config may also carry a literal rpc_url as a last resort.
    """
    attack = getattr(cfg, "attack", None) or {}
    solid = getattr(cfg, "solidity", None) or {}
    for key in (attack.get("rpc_env"), solid.get("fork_rpc_env"), "ETH_RPC_URL"):
        if key and os.environ.get(key):
            return os.environ[key]
    return attack.get("rpc_url") or solid.get("rpc_url") or ""


def run_cmd(cmd, cwd=None, timeout=900, env=None) -> dict:
    env = {**os.environ, **env} if env else None
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, timeout=timeout,
                           env=env, capture_output=True, text=True, errors="replace")
        return {"cmd": cmd if isinstance(cmd, str) else " ".join(map(str, cmd)),
                "rc": p.returncode, "out": p.stdout or "", "err": p.stderr or "",
                "dur": round(time.time() - t0, 2), "ok": p.returncode == 0}
    except subprocess.TimeoutExpired:
        return {"cmd": str(cmd), "rc": -9, "out": "", "err": f"timeout {timeout}s",
                "dur": round(time.time() - t0, 2), "ok": False}
    except FileNotFoundError:
        return {"cmd": str(cmd), "rc": -2, "out": "", "err": "binary not found",
                "dur": 0.0, "ok": False}
    except Exception as exc:
        return {"cmd": str(cmd), "rc": -1, "out": "", "err": str(exc),
                "dur": round(time.time() - t0, 2), "ok": False}


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S", stream=sys.stderr)
    for noisy in ("urllib3", "requests", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)