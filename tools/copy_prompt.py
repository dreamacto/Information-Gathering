#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""复制一个配方文件到 Windows 剪贴板（纯 stdlib，无第三方依赖）。

用法:
    python tools\\copy_prompt.py A        # 复制 prompts\\配方A_复盘会话.md
    python tools\\copy_prompt.py 6        # 同上（数字别名 1-6）
    python tools\\copy_prompt.py --list   # 列出全部配方

剪贴板写入: subprocess 调用 powershell.exe Set-Clipboard，内容经 base64 传参，
避免中文/编码经命令行损坏。
"""
import base64
import os
import subprocess
import sys

RECIPES = {
    "A": "配方A_复盘会话.md",
    "B": "配方B_规划会话.md",
    "C": "配方C_单目标深挖.md",
    "D": "配方D_逻辑漏洞工作坊.md",
    "E": "配方E_周度沉淀.md",
    "F": "配方F_白盒研判.md",
    "P": "配方P_提示词分发员.md",
    "Z": "配方Z_全流程验收.md",
}
ALIASES = {"1": "A", "2": "B", "3": "C", "4": "D", "5": "E", "6": "F", "7": "P"}


def rec_files():
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(base, "..", "prompts"))


def list_recipes():
    for key in "ABCDEFPZ":
        path = os.path.join(rec_files(), RECIPES[key])
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8-sig") as handle:
                size = len(handle.read())
            print(f"  {key}  ->  {RECIPES[key]}  [{size} chars / OK]")
        else:
            print(f"  {key}  ->  {RECIPES[key]}  [MISSING]")


def copy_to_clipboard(text):
    payload = base64.b64encode(text.encode("utf-8")).decode("ascii")
    # 命令行长度防护：Windows CreateProcess 上限约 32767 字符，base64 留 1/3 余量。
    if len(payload) > 20000:
        raise ValueError(f"recipe too large for clipboard command line ({len(payload)} b64 chars)")
    command = (
        "powershell.exe -NoProfile -NonInteractive -Command "
        '"$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\'{0}\'));'
        'Set-Clipboard -Value $t"'
    ).format(payload)
    subprocess.run(command, check=True)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print("usage: python copy_prompt.py <A-F/Z|1-6> | --list")
        list_recipes()
        return 0
    if args[0] == "--list":
        list_recipes()
        return 0
    key = args[0].strip().upper()
    key = ALIASES.get(key, key)
    if key not in RECIPES:
        print(f"[ERROR] Unknown recipe key: {args[0]}")
        list_recipes()
        return 2
    path = os.path.join(rec_files(), RECIPES[key])
    if not os.path.exists(path):
        print(f"[ERROR] Recipe file not found: {path}")
        return 2
    with open(path, "r", encoding="utf-8-sig") as handle:
        text = handle.read()
    try:
        copy_to_clipboard(text)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"[ERROR] Clipboard write failed: {exc}")
        return 1
    print(f"[OK] 配方 {key}（{RECIPES[key]}，{len(text)} 字符）已复制到剪贴板，直接粘贴给你的 AI。")
    return 0


if __name__ == "__main__":
    sys.exit(main())