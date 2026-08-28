@echo off

chcp 65001 >nul

setlocal



set "PROJECT=D:\PythonSource\PythonProjects\PythonProject4"
set "PY=%PROJECT%\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=D:\Desktop\天狐渗透工具箱-社区版V3.0+4.0更新升级包\天狐渗透工具箱-社区版V3.0\python3\python.exe"
if not exist "%PY%" set "PY=C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if not exist "%PY%" set "PY=python"
echo Using Python: %PY%



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



echo 保守全流程：尽可能多收集信息，同时保持低速、低并发、避 WAF。

echo 目标文件: %TARGETS%

echo.

echo 会运行：

echo   - 批量友好的低速 DNS 子域名发现，只写待确认/下一轮回流文件

echo   - 低速首页探活和内置分类

echo   - httpx 工具指纹，单线程、rate-limit=1

echo   - Katana 同站爬取，depth=2、concurrency=1、rate-limit=1、delay=5s

echo   - JS/API 线索提取 + 小批量 API 元数据确认

echo   - SQLi 低影响 GET 差分候选筛选，小批量、只写元数据

echo   - Shiro rememberMe 轻量候选筛选，小批量、不爆破 key

echo   - XSS 安全 GET 标记反射检查，不发脚本 payload

echo   - 二次轻量复测、指纹后深入分支、P0-P3 候选总表、每目标画像

echo   - 产品漏洞候选队列、小程序/微信离线线索包

echo.

echo 会跳过：

echo   - 高价值固定路径检查

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

  --api-confirm ^

  --api-confirm-threshold 4 ^

  --api-confirm-max-per-target 4 ^

  --sqli-triage ^

  --sqli-limit 30 ^

  --sqli-max-per-host 2 ^

  --shiro-triage ^

  --shiro-limit 10 ^

  --xss-triage ^

  --xss-reflect-check ^

  --xss-limit 80 ^

  --xss-max-per-host 3 ^

  --second-pass-triage ^

  --second-pass-sql-limit 6 ^

  --second-pass-xss-limit 10 ^

  --second-pass-api-limit 10 ^

  --review-intelligence ^

  --fingerprint-deepening ^

  --miniapp-search-pack ^

  --wechat-miniapp ^

  --delay 5 ^
  --max-concurrency 1



set "RC=%ERRORLEVEL%"

echo.

if not "%RC%"=="0" echo 流程执行失败，错误码: %RC%

pause

exit /b %RC%

