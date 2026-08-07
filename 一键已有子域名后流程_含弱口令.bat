@echo off
chcp 65001 >nul
setlocal EnableExtensions DisableDelayedExpansion

set "PROJECT=D:\PythonSource\PythonProjects\PythonProject4"
set "WORKFLOW=%PROJECT%\parallel_flow_runner.py"
set "BUNDLED_PY=C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
set "PROJECT_PY=%PROJECT%\.venv\Scripts\python.exe"
set "PY="
set "PLAN_ONLY="

if /I "%~2"=="--plan-only" set "PLAN_ONLY=--plan-only"

if exist "%BUNDLED_PY%" set "PY=%BUNDLED_PY%"
if not defined PY if exist "%PROJECT_PY%" set "PY=%PROJECT_PY%"
if not defined PY (
  where python.exe >nul 2>&1
  if not errorlevel 1 set "PY=python.exe"
)

if not defined PY (
  echo [ERROR] No usable Python runtime was found.
  echo Check the bundled Python path or the project virtual environment.
  goto :failed
)

if not exist "%WORKFLOW%" (
  echo [ERROR] Workflow script not found:
  echo %WORKFLOW%
  goto :failed
)

if "%~1"=="" (
  set /p "TARGETS=Enter the existing subdomain target-file path: "
) else (
  set "TARGETS=%~1"
)

if not defined TARGETS (
  echo [ERROR] No target-file path was provided.
  goto :failed
)

rem Accept a pasted quoted path and normalize it to an absolute path.
set "TARGETS=%TARGETS:"=%"
for %%I in ("%TARGETS%") do set "TARGETS=%%~fI"

if not exist "%TARGETS%" (
  echo [ERROR] Target file does not exist:
  echo %TARGETS%
  goto :failed
)

if exist "%TARGETS%\NUL" (
  echo [ERROR] The target path is a directory, not a file:
  echo %TARGETS%
  goto :failed
)

echo Starting the authorized post-subdomain workflow in up to 3 parallel batches.
echo Targets are balanced by root domain; the same root domain stays in one batch.
echo Weak-credential review is enabled and requires exercise approval.
echo XSS checking uses a safe GET reflection marker, not a script payload.
echo Target file: %TARGETS%
if defined PLAN_ONLY echo Plan-only mode: no workflow workers will be launched.
echo.

pushd "%PROJECT%" >nul
if errorlevel 1 (
  echo [ERROR] Cannot enter the project directory:
  echo %PROJECT%
  goto :failed
)

"%PY%" "%WORKFLOW%" ^
  --targets "%TARGETS%" ^
  --workspace "%PROJECT%" ^
  --runner-python "%PY%" ^
  --batch-count 3 ^
  --max-parallel 3 ^
  --group-mode root-domain ^
  --label one_click_subdomains_parallel ^
  --delay 3 ^
  %PLAN_ONLY% ^
  -- ^
  --probe ^
  --fingerprint ^
  --tool-fingerprint ^
  --high-value-paths ^
  --api-discovery ^
  --api-confirm ^
  --api-use-katana ^
  --sqli-triage ^
  --sqli-limit 16 ^
  --shiro-triage ^
  --shiro-limit 10 ^
  --xss-triage ^
  --xss-reflect-check ^
  --xss-limit 26 ^
  --xss-max-per-host 3 ^
  --weak-credential-review ^
  --weak-credential-max-targets 3 ^
  --weak-credential-max-pairs 5
set "RC=%ERRORLEVEL%"
popd >nul

echo.
if not "%RC%"=="0" (
  echo [ERROR] Workflow failed with return code %RC%.
) else (
  echo Workflow completed.
)
pause
exit /b %RC%

:failed
echo.
pause
exit /b 2
