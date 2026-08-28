@echo off
rem Compatibility wrapper; canonical launcher lives in launchers\一键并行分批流程.bat
call "%~dp0launchers\一键并行分批流程.bat" %*
exit /b %ERRORLEVEL%
