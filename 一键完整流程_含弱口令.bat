@echo off
rem Compatibility wrapper; canonical launcher lives in launchers\一键完整流程_含弱口令.bat
call "%~dp0launchers\一键完整流程_含弱口令.bat" %*
exit /b %ERRORLEVEL%
