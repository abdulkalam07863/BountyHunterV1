@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\activate.bat" python -m venv .venv
call ".venv\Scripts\activate.bat" || goto :fail

python -m pip install --upgrade pip --timeout 60 --resume-retries 20
python -m pip install requests pyyaml rich beautifulsoup4 --timeout 60 --resume-retries 20
python -m pip install slither-analyzer bandit --timeout 60 --resume-retries 20 || goto :fail
python -m pip install semgrep vyper --timeout 120

if not exist ".env" if exist ".env.example" copy ".env.example" ".env" >nul

python verify.py
goto :eof

:fail
echo.
echo Setup failed - see the error above.
exit /b 1