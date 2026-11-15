#Requires -Version 5.1
$ErrorActionPreference = "Continue"

Write-Host "== Python deps ==" -ForegroundColor Cyan
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pip-audit semgrep bandit njsscan slither-analyzer mythril

Write-Host "== Foundry ==" -ForegroundColor Cyan
if (-not (Get-Command foundryup -ErrorAction SilentlyContinue)) {
    try {
        Invoke-WebRequest -Uri "https://foundry.paradigm.xyz" -UseBasicParsing | Invoke-Expression
    } catch { Write-Host "foundryup install failed" -ForegroundColor Yellow }
}
if (Get-Command foundryup -ErrorAction SilentlyContinue) { foundryup }

Write-Host "== Go tools ==" -ForegroundColor Cyan
if (Get-Command go -ErrorAction SilentlyContinue) {
    go install github.com/securego/gosec/v2/cmd/gosec@latest
} else { Write-Host "go missing - gosec skipped" -ForegroundColor Yellow }

Write-Host "== winget tools ==" -ForegroundColor Cyan
foreach ($p in @("Git.Git", "aquasecurity.trivy", "Google.OSVScanner",
                 "Gitleaks.Gitleaks", "TruffleSecurity.TruffleHog")) {
    winget install --id $p --accept-source-agreements --accept-package-agreements --silent
}
if (Get-Command cargo -ErrorAction SilentlyContinue) { cargo install aderyn }
else { Write-Host "cargo missing - aderyn skipped" -ForegroundColor Yellow }

if (-not (Test-Path "D:\")) { Write-Host "`nD: not mounted - falls back to C:\BugBounty" -ForegroundColor Yellow }
New-Item -ItemType Directory -Force -Path "D:\BugBounty" | Out-Null

Write-Host "`n== Verify ==" -ForegroundColor Cyan
python verify.py
