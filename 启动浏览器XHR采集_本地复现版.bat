@echo off
rem Compatibility wrapper; canonical launcher lives in launchers\启动浏览器XHR采集_本地复现版.bat
call "%~dp0launchers\启动浏览器XHR采集_本地复现版.bat" %*
exit /b %ERRORLEVEL%
