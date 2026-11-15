"""Repository acquisition.

Full blobless clone - no sparse checkout - so cross-directory Solidity
imports resolve. Re-running over an existing checkout updates in place
instead of dying on 'destination path already exists'.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

RETRIES = 3
NPM_TIMEOUT = int(os.environ.get("BH_NPM_TIMEOUT", "420"))

# Scopes that actually get remapped into node_modules. Anything else in
# package.json (hardhat, ethers, jest, typechain...) is dead weight for solc.
NPM_SCOPES = ("@openzeppelin", "@uniswap", "@chainlink", "@balancer-labs",
              "@aave", "@curvefi", "@pendle", "@layerzerolabs")

# Shared cache outside every repo, so --prefer-offline is warm from repo 2 onward.
NPM_CACHE = Path(os.environ.get("BH_NPM_CACHE") or Path.home() / ".bh-npm-cache")

_IMPORT_RX = re.compile(r"""import\s+(?:[^;]*?\s+from\s+)?["']([^"']+)["']""")


class CloneError(RuntimeError):
    """Raised when a repository cannot be acquired."""


def _run(argv, cwd=None, timeout=900, stream=False, env=None):
    """Resolve the executable and wrap .cmd/.bat - CreateProcess cannot exec them."""
    exe = shutil.which(argv[0])
    if exe:
        argv = [exe, *argv[1:]]
        if os.name == "nt" and exe.lower().endswith((".cmd", ".bat")):
            argv = ["cmd", "/c", *argv]
    kw = dict(cwd=cwd, text=True, encoding="utf-8", errors="replace")
    if env:
        kw["env"] = env
    if stream:
        return subprocess.run(argv, timeout=timeout, **kw)
    return subprocess.run(argv, capture_output=True, timeout=timeout, **kw)


def _git(*args, cwd=None):
    return _run(["git", *args], cwd=cwd)


def _quarantine(dest: Path) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest.rename(dest.with_name(f"{dest.name}.bak-{stamp}"))


def _default_ref(dest: Path):
    ref = _git(
        "-C", str(dest), "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"
    ).stdout.strip()
    if ref:
        return ref.replace("refs/remotes/", "")
    for cand in ("origin/main", "origin/master"):
        if _git("-C", str(dest), "rev-parse", "--verify", "--quiet", cand).returncode == 0:
            return cand
    out = _git(
        "-C", str(dest), "for-each-ref", "--format=%(refname:short)",
        "refs/remotes/origin",
    ).stdout.split()
    return out[0] if out else None


def _needs_node_modules(dest: Path, limit: int = 4000) -> bool:
    """Only worth an npm install if some in-scope .sol actually imports from a
    package. Most repos that ship a package.json for tests never need it."""
    skip = {"node_modules", "lib", ".git", "out", "cache", "artifacts"}
    checked = 0
    for sol in dest.rglob("*.sol"):
        if skip & set(sol.parts):
            continue
        if checked >= limit:
            break
        checked += 1
        try:
            text = sol.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _IMPORT_RX.finditer(text):
            spec = m.group(1)
            if spec.startswith(NPM_SCOPES) or spec.startswith("node_modules/"):
                return True
    return False


def _write_remappings(dest: Path) -> None:
    mods = dest / "node_modules"
    if not mods.is_dir():
        return
    wanted = [f"{s}/=node_modules/{s}/" for s in NPM_SCOPES if (mods / s).is_dir()]
    if not wanted:
        return
    path = dest / "remappings.txt"
    existing = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    have = {l.strip() for l in existing.splitlines()}
    added = [w for w in wanted if w not in have]
    if added:
        path.write_text(existing.rstrip("\n") + ("\n" if existing.strip() else "")
                        + "\n".join(added) + "\n", encoding="utf-8")


def _bootstrap(dest: Path) -> None:
    if os.environ.get("BH_SKIP_NPM"):
        print(f"NOTE {dest.name}: BH_SKIP_NPM set - no deps installed")
        return

    pkg = dest / "package.json"
    if pkg.is_file() and not (dest / "node_modules").is_dir():
        npm = shutil.which("npm")
        if not npm:
            print(f"WARN {dest.name}: package.json but no npm - build will fail")
            return
        if not _needs_node_modules(dest):
            print(f"NOTE {dest.name}: no .sol imports a package - npm install skipped")
        else:
            lock = dest / "package-lock.json"
            had_lock = lock.is_file()
            if had_lock:
                cmd = [npm, "ci", "--ignore-scripts", "--omit=dev", "--prefer-offline",
                       "--no-fund", "--no-audit", "--no-progress", "--legacy-peer-deps"]
            else:
                cmd = [npm, "install", "--ignore-scripts", "--omit=dev", "--prefer-offline",
                       "--no-fund", "--no-audit", "--no-progress", "--legacy-peer-deps"]
            NPM_CACHE.mkdir(parents=True, exist_ok=True)
            env = {
                **os.environ,
                "npm_config_cache": str(NPM_CACHE),
                "npm_config_omit": "dev",
                "npm_config_fund": "false",
                "npm_config_audit": "false",
                "npm_config_progress": "false",
                "npm_config_legacy_peer_deps": "true",
            }
            env.setdefault("npm_config_registry", "https://registry.npmmirror.com")
            print(f"installing npm deps for {dest.name} (cached, dev deps omitted)")
            t0 = time.time()
            try:
                r = _run(cmd, cwd=dest, timeout=NPM_TIMEOUT, stream=True, env=env)
                if r.returncode != 0:
                    print(f"WARN {dest.name}: npm install rc={r.returncode} - "
                          f"imports may not resolve")
            except subprocess.TimeoutExpired:
                print(f"WARN {dest.name}: npm install timed out after {NPM_TIMEOUT}s - "
                      f"continuing without deps")
            else:
                print(f"npm deps ready for {dest.name} in {time.time() - t0:.0f}s")
                if had_lock and not (dest / "node_modules").is_dir():
                    _git("-C", str(dest), "checkout", "--", "package-lock.json")

    _write_remappings(dest)
    if not shutil.which("vyper"):
        print(f"NOTE {dest.name}: vyper not on PATH - Vyper sources will not compile")


def _update(dest: Path, branch=None) -> None:
    _git("-C", str(dest), "config", "core.sparseCheckout", "false")
    _git("-C", str(dest), "sparse-checkout", "disable")
    f = _git("-C", str(dest), "fetch", "--all", "--prune", "--tags")
    if f.returncode != 0:
        print(f"WARN {dest.name}: fetch failed: {f.stderr.strip()[:200]}")
    target = branch or _default_ref(dest)
    if not target:
        raise CloneError(f"{dest.name}: cannot resolve a default branch")
    if not target.startswith("origin/"):
        target = f"origin/{target}"
    r = _git("-C", str(dest), "reset", "--hard", target)
    if r.returncode != 0:
        print(f"WARN {dest.name}: reset to {target} failed: {r.stderr.strip()[:200]}")
        _git("-C", str(dest), "checkout", "-f", target)
    # -e node_modules keeps the install cache alive across re-runs.
    _git("-C", str(dest), "clean", "-fdx", "-e", "node_modules")
    if not any(dest.rglob("*.sol")):
        print(f"WARN {dest.name}: no .sol files after update - checkout incomplete")


def clone_repo(url: str, branch=None, dest=None) -> Path:
    if dest is None:
        dest, branch = branch, None
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists():
        if (dest / ".git").is_dir():
            _update(dest, branch)
            _bootstrap(dest)
            return dest
        if any(dest.iterdir()):
            _quarantine(dest)
        else:
            dest.rmdir()

    args = ["clone", "--filter=blob:none"]
    if branch:
        args += ["--branch", branch]
    args += [url, str(dest)]

    last = None
    for attempt in range(1, RETRIES + 1):
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        r = _git(*args)
        if r.returncode == 0:
            _bootstrap(dest)
            return dest
        last = r
        time.sleep(2 * attempt)

    detail = ((last.stderr or last.stdout) if last else "").strip()[:800]
    raise CloneError(f"clone failed after {RETRIES} attempts: {url}\n{detail}")


def sparse_clone(url: str, dest, paths=None) -> Path:
    """Compat alias - sparse paths are filtered at scan time now."""
    return clone_repo(url, None, dest)