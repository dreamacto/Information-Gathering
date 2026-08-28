@echo off
chcp 65001 >nul
setlocal

set PROJECT_DIR=%~dp0..
set NODE_EXE=C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe
if exist "%NODE_EXE%" goto run

set NODE_EXE=C:\Program Files\nodejs\node.exe
if exist "%NODE_EXE%" goto run

echo Node.js not found. Please install Node.js or check node.exe path.
pause
exit /b 1

:run
echo Browser XHR/FETCH capture with local replay is starting...
echo Node: %NODE_EXE%
"%NODE_EXE%" --version
echo.
echo Warning: local replay mode may save Cookie/Authorization into .local files.
echo Do not submit those files with reports or upload them to source control.
echo.
"%NODE_EXE%" "%PROJECT_DIR%tools\browser_xhr_capture.mjs" --save-local-replay %*
echo.
pause
exit /b %ERRORLEVEL%
