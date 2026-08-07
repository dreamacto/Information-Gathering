@echo off
chcp 65001 >nul
setlocal

set "ROOT=%~dp0"
set "PY=C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if not exist "%PY%" set "PY=python"

if "%~1"=="" (
  set /p "BURP=Burp XML/TXT path, or TXT pasted from copied HTTP history: "
) else (
  set "BURP=%~1"
)

if "%BURP%"=="" (
  echo No Burp file path provided.
  pause
  exit /b 2
)

echo Miniapp Burp import into latest run
echo Burp file: %BURP%
echo.

"%PY%" "%ROOT%miniapp_burp_import_latest.py" --burp-export "%BURP%"
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" echo Import failed, error code: %RC%
pause
exit /b %RC%
