from __future__ import annotations

import re
from pathlib import Path

TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^{pragma};

import "forge-std/Test.sol";

/// @title PoC - {title}
/// @notice {fid} ({severity}, CVSS~{cvss}) in {file}
/// @dev Run: forge test --match-contract {contract} -vvvv --fork-url $ETH_RPC_URL
contract {contract} is Test {{
    address constant TARGET = {target};
    address constant ATTACKER = address(0xA11CE);
    address constant VICTIM   = address(0xB0B);

    function setUp() public {{
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));
        vm.deal(ATTACKER, 100 ether);
        vm.startPrank(ATTACKER);
    }}

    function test_exploit() public {{
        uint256 balBefore = address(ATTACKER).balance;

        // 1. TODO reach the sink in {file}
        // 2. TODO trigger the bug
        // 3. TODO assert the gain

        // assertGt(address(ATTACKER).balance, balBefore);
        vm.stopPrank();
    }}
}}
'''

PRAGMA_RX = re.compile(r"pragma\s+solidity\s+[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)")


def _pragma(repo: Path | None) -> str:
    """Match the target's pragma - a hardcoded 0.8.20 will not compile a 0.7.x tree."""
    if repo is not None and repo.exists():
        seen = []
        for sol in list(repo.rglob("*.sol"))[:400]:
            if any(p in {"test", "lib", "node_modules"} for p in sol.parts):
                continue
            try:
                m = PRAGMA_RX.search(sol.read_text(encoding="utf-8", errors="replace")[:4000])
            except OSError:
                continue
            if m:
                seen.append(m.group(1))
        if seen:
            return max(seen, key=lambda v: tuple(int(x) for x in v.split(".")))
    return "0.8.20"


def _name(fid: str, title: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9]+", "_", title)[:40].strip("_")
    return f"PoC_{fid.replace('-', '')}_{stem}"


def generate(project_path: Path, findings: list, scope: dict,
             fallback_address: str | None = None, repo: Path | None = None) -> list:
    out_dir = project_path / "poc" / "test"
    out_dir.mkdir(parents=True, exist_ok=True)
    pragma = _pragma(repo)
    addrs = scope.get("addresses") or ([fallback_address] if fallback_address else [])
    written, used = [], set()
    for f in findings:
        if len(written) >= 10:
            break
        if f["severity"] not in ("critical", "high"):
            continue
        name = _name(f["fid"], f["title"])
        while name in used:
            name += "_"
        used.add(name)
        body = TEMPLATE.format(pragma=pragma, title=f["title"], fid=f["fid"],
                               severity=f["severity"], cvss=f["cvss"],
                               file=f.get("file") or "?",
                               contract=name, target=addrs[0] if addrs else "address(0)")
        p = out_dir / f"{name}.t.sol"
        p.write_text(body, encoding="utf-8")
        written.append(p)
    return written