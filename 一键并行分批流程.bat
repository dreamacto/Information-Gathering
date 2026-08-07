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

set "AUTO_BATCH=--auto-batch"
if "%~2"=="" (
  set "BATCH_SIZE=300"
) else (
  set "BATCH_SIZE=%~2"
  set "AUTO_BATCH="
)

if "%~3"=="" (
  set "MAX_PARALLEL=3"
) else (
  set "MAX_PARALLEL=%~3"
)

echo 并行分批只读流程
echo 目标文件: %TARGETS%
if "%AUTO_BATCH%"=="" (
  echo 每批数量: %BATCH_SIZE%
) else (
  echo 批次数量: 自动，根据目标总数动态计算
)
echo 同时批数: %MAX_PARALLEL%
echo 分组方式: root-domain，同一根域不会分到多个并行批次
echo.

"%PY%" "%PROJECT%\parallel_flow_runner.py" ^
  --targets "%TARGETS%" ^
  --workspace "%PROJECT%" ^
  --runner-python "%PY%" ^
  --batch-size %BATCH_SIZE% ^
  %AUTO_BATCH% ^
  --max-parallel %MAX_PARALLEL% ^
  --group-mode root-domain ^
  --profile readonly ^
  --delay 3

set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" echo 并行流程执行失败，错误码: %RC%
pause
exit /b %RC%
