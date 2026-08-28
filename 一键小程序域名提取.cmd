@echo off
rem Compatibility wrapper; canonical launcher lives in launchers\一键小程序域名提取.cmd
call "%~dp0launchers\一键小程序域名提取.cmd" %*
exit /b %ERRORLEVEL%
