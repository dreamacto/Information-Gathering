@echo off
chcp 65001 >nul
setlocal

set "PROJECT=D:\PythonSource\PythonProjects\PythonProject4"
set "PY=C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if not exist "%PY%" set "PY=python"

if "%~1"=="" (
  set /p "TARGETS=请输入目标文件路径: "
) else (
  set "TARGETS=%~1"
)

if "%TARGETS%"=="" (
  echo 未提供目标文件路径。
  pause
  exit /b 2
)

echo 保守全流程：尽可能多收集信息，同时尽量规避 WAF。
echo 目标文件: %TARGETS%
echo.
echo 会运行：
echo   - 批量友好的低速 DNS 子域名发现，只写待确认/下一轮回流文件
echo   - 低速首页探活和内置分类
echo   - httpx 工具指纹，单线程、rate-limit=1
echo   - Katana 同站爬取，depth=2、concurrency=1、rate-limit=1、delay=5s
echo   - JS/API 线索提取、产品漏洞候选队列、小程序/微信离线线索包
echo   - XSS 安全 GET 标记反射检查，不发脚本 payload
echo.
echo 会跳过：
echo   - 高价值固定路径检查
echo   - API 自动确认
echo   - SQLi 低影响探测
echo   - Shiro rememberMe 探测
echo   - 弱口令复核
echo.

"%PY%" "%PROJECT%\gov_exercise_runner.py" ^
  --targets "%TARGETS%" ^
  --label one_click_conservative_info ^
  --subdomain-bruteforce ^
  --subdomain-delay 2.5 ^
  --subdomain-qps 1.2 ^
  --subdomain-concurrency 6 ^
  --subdomain-max-words 40 ^
  --subdomain-max-roots 300 ^
  --subdomain-max-queries 12000 ^
  --probe ^
  --fingerprint ^
  --tool-fingerprint ^
  --api-discovery ^
  --api-use-katana ^
  --api-max-js 30 ^
  --xss-triage ^
  --xss-reflect-check ^
  --xss-limit 80 ^
  --xss-max-per-host 3 ^
  --miniapp-search-pack ^
  --wechat-miniapp ^
  --delay 5

set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" echo 流程执行失败，错误码: %RC%
pause
exit /b %RC%
