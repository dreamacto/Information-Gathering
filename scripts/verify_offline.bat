@echo off
setlocal
set "ROOT=%~dp0.."
cd /d "%ROOT%"
set "PY=%ROOT%\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" "%ROOT%\scripts\verify_offline.py" %*
exit /b %ERRORLEVEL%
