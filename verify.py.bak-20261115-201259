#!/usr/bin/env python3
"""Post-install self check. Run before auditing anything."""
from __future__ import annotations

import os
import shutil
import sys

import bh  # noqa: F401  (loads .env)

TOOLS = ["git", "python", "forge", "slither", "aderyn", "myth", "echidna",
         "semgrep", "bandit", "gitleaks", "trivy", "osv-scanner", "trufflehog"]

REQUIRED = {"git", "python", "forge", "slither"}


def main() -> int:
    print("toolchain\n---------")
    missing_required, missing_optional = [], []
    for t in TOOLS:
        ok = shutil.which(t) is not None
        print(f"  {'OK  ' if ok else 'MISS'}  {t}")
        if not ok:
            (missing_required if t in REQUIRED else missing_optional).append(t)

    print("\npython modules\n--------------")
    for mod in ("requests", "yaml", "rich", "bs4"):
        try:
            __import__(mod)
            print(f"  OK    {mod}")
        except ImportError:
            print(f"  MISS  {mod}")
            missing_required.append(mod)

    print("\nenvironment\n-----------")
    rpc = os.environ.get("ETH_RPC_URL")
    print(f"  ETH_RPC_URL  {'set' if rpc else 'MISSING (PoCs cannot fork)'}")

    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import bh.cli  # noqa: F401
        print("  package import  OK")
    except Exception as exc:
        print(f"  package import  FAILED: {exc}")
        missing_required.append("bh package")

    print("\nfoundry toolchain\n-----------------")
    from bh.audit.solidity import ensure_foundry_config
    from pathlib import Path
    print(f"  solc            {'OK  ' if shutil.which('solc') or shutil.which('solc-select') else 'MISS (forge installs one)'}")
    print(f"  config helper   {'OK' if callable(ensure_foundry_config) else 'MISS'}")
    print(f"  rules/custom.yaml {'OK' if (Path(__file__).parent / 'rules' / 'custom.yaml').is_file() else 'MISS'}")

    if missing_required:
        print(f"\nBLOCKING: {', '.join(missing_required)}")
        return 1
    if missing_optional:
        print(f"\nDegraded (audits still run): {', '.join(missing_optional)}")
    print("\nReady.")
    return 0


if __name__ == "__main__":
    sys.exit(main())