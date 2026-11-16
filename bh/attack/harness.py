from __future__ import annotations

import json
import re
from pathlib import Path

from ..util import have_tool, log, run_cmd
from .vectors import VECTORS, Sig

SKIP_PART = {"lib", "node_modules", "test", "tests", "mock", "mocks", "script",
             "interfaces", "interface", "out", "cache"}
NAME_SKIP = ("Interface", "Test", "Mock", "Script", "Storage", "Errors", "Events")

BASE = r"""
// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.0 <0.9.0;

import {Test, Vm} from "forge-std/Test.sol";

interface IERC20Min {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function decimals() external view returns (uint8);
}
interface IERC4626Min {
    function asset() external view returns (address);
    function balanceOf(address) external view returns (uint256);
}
interface IPairMin {
    function token0() external view returns (address);
    function token1() external view returns (address);
}
interface IAgg { function latestAnswer() external view returns (int256); }

contract Reenterer {
    address internal tgt;
    bytes internal cd;
    address internal owner;
    uint256 public depth;
    bool internal armed;

    constructor(address _t, bytes memory _cd, address _o) { tgt = _t; cd = _cd; owner = _o; armed = true; }

    function fire(uint256) external payable {
        if (armed) { armed = false; depth++; (bool ok, ) = tgt.call(cd); ok; }
    }
    receive() external payable {
        if (armed) { armed = false; depth++; (bool ok, ) = tgt.call(cd); ok; }
    }
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }
    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external {
        if (armed) { armed = false; depth++; (bool ok, ) = tgt.call(cd); ok; }
    }
}

abstract contract BHBase is Test {
    Vm internal constant vmc = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address internal attacker;
    address internal target;
    string internal outPath;
    string internal _note;
    bool internal _structural;
    address[] internal tracked;
    uint256[] internal startBal;

    function _bhInit(address _target, string memory _name) internal {
        attacker = makeAddr("bh_attacker");
        target = _target;
        vm.deal(attacker, uint256(1000e18));
        outPath = string(abi.encodePacked("attack-results/", _name, ".json"));
    }

    function _track(address t) internal { tracked.push(t); }

    function _startSnap() internal {
        delete startBal;
        for (uint256 i; i < tracked.length; i++) startBal.push(_bal(tracked[i], attacker));
    }

    function _bal(address t, address who) internal view returns (uint256) {
        if (t == address(0)) return who.balance;
        (bool ok, bytes memory d) = t.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        return ok && d.length >= 32 ? abi.decode(d, (uint256)) : 0;
    }

    function _feed(address t) internal pure returns (address) {
        if (t == 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) return 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;
        if (t == 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) return 0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6;
        if (t == 0xdAC17F958D2ee523a2206206994597C13D831ec7) return 0x3E7d1eAB13ad0104d2750B8863b489D65364e32D;
        if (t == 0x6B175474E89094C44Da98b954EedeAC495271d0F) return 0xAed0c38402a5d19df6E4c03F4E2DceD6e29c1ee9;
        if (t == 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599) return 0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c;
        return address(0);
    }

    function _usd(address tok, int256 d) internal view returns (int256) {
        if (d <= 0 || block.chainid != 1) return 0;
        address f = _feed(tok);
        if (f == address(0)) return 0;
        uint8 dec;
        try IERC20Min(tok).decimals() returns (uint8 x) { dec = x; } catch { return 0; }
        int256 px;
        try IAgg(f).latestAnswer() returns (int256 p) { px = p; } catch { return 0; }
        return (d * px) / int256(10 ** dec);
    }

    function _report(string memory vector, string memory contractName) internal {
        string memory toks = "[";
        string memory dels = "[";
        int256 usd8;
        bool profit;
        for (uint256 i; i < tracked.length; i++) {
            int256 d = int256(_bal(tracked[i], attacker)) - int256(startBal[i]);
            if (d > 0) profit = true;
            usd8 += _usd(tracked[i], d);
            toks = string(abi.encodePacked(toks, i == 0 ? "" : ",", vm.toString(tracked[i])));
            dels = string(abi.encodePacked(dels, i == 0 ? "" : ",", vm.toString(d)));
        }
        string memory j = string(abi.encodePacked(
            '{"vector":"', vector, '","contract":"', contractName, '","tokens":', toks,
            ',"deltas":', dels, ',"profit":', profit ? "true" : "false",
            ',"structural":', _structural ? "true" : "false",
            ',"usd":', vm.toString(double(usd8) / 1e8),
            ',"note":"', _note, '"}'));
        vm.writeFile(outPath, j);
    }
}
"""


def _artifacts(repo: Path) -> list[dict]:
    out = repo / "out"
    if not out.is_dir():
        return []
    found = []
    for j in out.rglob("*.json"):
        if any(p in SKIP_PART for p in j.relative_to(repo).parts):
            continue
        if j.name.endswith(".metadata.json") or j.name.endswith(".dbg.json"):
            continue
        try:
            data = json.loads(j.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        abi = data.get("abi") or []
        bytecode = ((data.get("bytecode") or {}).get("object") or "")
        if not abi or len(bytecode) < 200:
            continue
        name = j.stem
        if any(name.endswith(s) for s in NAME_SKIP):
            continue
        found.append({"name": name, "artifact": j.relative_to(repo).as_posix(), "abi": abi})
    return found


def _targets(repo: Path, deployments: list[str]) -> list[dict]:
    arts = _artifacts(repo)
    if not arts:
        return []
    picked = []
    for a in arts:
        if any(k in a["name"].lower() for k in
               ("vault", "pool", "staking", "stake", "market", "controller", "router",
                "strategy", "erc4626", "gauge", "manager")):
            picked.append(a)
    for a in arts:
        if a not in picked:
            picked.append(a)
    for i, a in enumerate(picked[:12]):
        a["addr"] = deployments[i] if i < len(deployments) else None
    return picked[:12]


def _resolve(target: dict) -> tuple[str, str]:
    if target.get("addr"):
        return "use", f"        _bhInit({target['addr']}, \"{target['name']}\");"
    return "deploy", (
        f'        address t; try this._deploy("{target["artifact"]}") returns (address a) '
        f'{{ t = a; }} catch {{ return; }}\n'
        f'        _bhInit(t, "{target["name"]}");')


def run_harness(cfg, repo: Path, rpc: str, scope_paths=None) -> tuple[list, dict]:
    if not have_tool("forge"):
        return [], {"tool": "attack", "status": "forge missing"}
    deployments = _deployments(repo)
    targets = _targets(repo, deployments)
    if not targets:
        return [], {"tool": "attack", "status": "no targets"}

    work = repo / "test" / "bh"
    work.mkdir(parents=True, exist_ok=True)
    (repo / "attack-results").mkdir(exist_ok=True)

    generated = []
    for t in targets:
        sig = Sig(t["abi"])
        tests, notes = [], {}
        for name, vec in VECTORS.items():
            body = vec["applies"](sig, t)
            if not body:
                continue
            tests.append(f"    function test_bh_{name}() public {{\n{body}\n"
                         f'        _report("{name}", "{t["name"]}");\n    }}\n')
            notes[name] = vec
        if not tests:
            continue
        how, init = _resolve(t)
        src = (BASE + "\ncontract BH_" + re.sub(r"\W", "_", t["name"]) + " is BHBase {\n"
               f"    function _deploy(string memory p) external returns (address) "
               f"{{ return vm.deployCode(p); }}\n\n"
               f"    function setUp() public {{\n        vm.createSelectFork(vm.envString(\"BH_RPC\"));\n"
               f"{init}\n    }}\n\n" + "\n".join(tests) + "}\n")
        path = work / f"{re.sub(r'\\W', '_', t['name'])}.t.sol"
        path.write_text(src, encoding="utf-8")
        generated.append((path, t["name"], notes))

    if not generated:
        return [], {"tool": "attack", "status": "no applicable vectors"}

    res = run_cmd(["forge", "test", "--match-path", "test/bh/*.t.sol",
                   "--allow-paths", str(repo), "--gas-limit", "30000000", "-vv"],
                  cwd=repo, timeout=int(cfg.attack.get("timeout", 2400)),
                  env={**__import__("os").environ, "BH_RPC": rpc})

    results = []
    for p, name, notes in generated:
        for name_, vec in notes.items():
            f = repo / "attack-results" / f"{name_}.json"
            if not f.is_file():
                continue
            try:
                r = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            r["artifact"] = next((g[0].relative_to(repo).as_posix() for g in generated
                                  if g[1] == name), None)
            r["remediation"] = vec["remediation"]
            results.append(r)
            f.unlink(missing_ok=True)

    skipped = sum(1 for p, n, _ in generated) - len({r["contract"] for r in results})
    if not res["ok"] and not results:
        log.warning("attack run failed:\n%s", (res["err"] or res["out"])[-1500:])
    return results, {"tool": "attack", "status": "ok" if res["ok"] else f"rc={res['rc']}",
                     "skipped": max(skipped, 0)}


def _deployments(repo: Path) -> list[str]:
    hits = []
    for d in ("deployments", "broadcast", "addresses"):
        base = repo / d
        if not base.is_dir():
            continue
        for f in base.rglob("*"):
            if f.is_file():
                hits += re.findall(r"0x[a-fA-F0-9]{40}", f.read_text(errors="replace"))
    seen, out = set(), []
    for h in hits:
        if h.lower() not in seen:
            seen.add(h.lower())
            out.append(h)
    return out