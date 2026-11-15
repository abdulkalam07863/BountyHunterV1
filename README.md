# bountyhunter

Bounty discovery and deep security audit pipeline. Windows-first, Python 3.11+.

## Install

```powershell
cd D:\tools\bountyhunter
python -m venv .venv
.\.venv\Scripts\Activate.ps1
.\setup.ps1
python verify.py
```

## Target a program

```powershell
$env:ETH_RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/KEY"
python bh.py target https://docs.aladdin.club/security-bounty
python bh.py target https://docs.aladdin.club/security-bounty --go
```

Writes to `D:\BugBounty\target\<slug>\`: `scope.json`, `repo/`, `reports/`, `poc/`.

## Discover new programs

```powershell
python bh.py discover -k "defi protocol"
python bh.py docs --limit 200
python bh.py list --status verified
```

## Commands

| command | purpose |
|---|---|
| `target <url>` | intake a bounty page, clone in-scope repos, audit |
| `docs` | hunt bounty policies on docs subdomains |
| `discover` | search platforms and X |
| `links <kw>` | generate research links |
| `list` / `show` / `clone` / `audit` | per-project workflow |
| `run` | end-to-end over discovered candidates |

## Reading results

Severity is a lead, not a verdict. Before writing anything up:

1. Read `<repo>/audit-reports/` — prior findings are likely duplicates.
2. Confirm the cited file is inside an in-scope path, not `archived/`.
3. For DeFi findings, build the fork PoC and show before/after balances.
