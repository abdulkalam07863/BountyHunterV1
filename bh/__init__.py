"""Package init.

Loads .env before any module reads the environment. bh.py and verify.py both
import this on line 1, so the RPC is in os.environ before config, clone, audit
or attack code runs. Values already present in the real environment win, so a
shell override still works.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(path: Path) -> None:
    try:
        raw = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        if key and not os.environ.get(key):
            os.environ[key] = val


for _name in (".env", ".env.local"):
    _load(ROOT / _name)