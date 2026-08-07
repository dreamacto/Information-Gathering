@echo off
chcp 65001 >nul
setlocal EnableExtensions DisableDelayedExpansion

set "PROJECT=D:\PythonSource\PythonProjects\PythonProject4"
set "PY=C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"

if not exist "%PROJECT%\one_click_workflow.py" (
  echo [ERROR] Project path not found: "%PROJECT%"
  pause
  exit /b 2
)

if not exist "%PY%" (
  set "PY=py"
)

if "%~1"=="" (
  set /p "TARGETS=Drag or paste target file path, then press Enter: "
) else (
  set "TARGETS=%~1"
)

rem Strip quotes added by drag-and-drop into cmd input.
set "TARGETS=%TARGETS:"=%"

if "%TARGETS%"=="" (
  echo [ERROR] No target file path was provided.
  pause
  exit /b 2
)

if not exist "%TARGETS%" (
  echo [ERROR] Target file not found: "%TARGETS%"
  pause
  exit /b 2
)

echo [INFO] Full workflow with explicit weak-credential review.
echo [INFO] Confirm scope and authorization before continuing.
echo [INFO] Target file: "%TARGETS%"
echo.

call "%PY%" "%PROJECT%\one_click_workflow.py" --mode full --targets "%TARGETS%"
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" echo [ERROR] Workflow failed, exit code: %RC%
pause
exit /b %RC%
