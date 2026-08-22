#!/usr/bin/env python3
"""check_doc_drift.py —— 文档/技能引用路径漂移 CI（20260822 复盘 P2）。

扫描关键文档里引用的本仓库脚本/文件路径，逐一验证存在性；
不存在 = 文档漂移（fh skill 曾引用不存在的 init_postrun_review.py）。

用法：python scripts/check_doc_drift.py   （退出码非 0 = 有漂移，可挂周报/CI）
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DOCS = [
    "AGENTS.md",
    "ROE.md",
    "AGENT_MANIFEST.md",
    "prompts/配方A_复盘会话.md",
    "prompts/配方B_规划会话.md",
    "prompts/配方C_单目标深挖.md",
    "prompts/配方D_逻辑漏洞工作坊.md",
    "prompts/配方E_周度沉淀.md",
    "prompts/配方F_白盒研判.md",
    ".agents/skills/wz/SKILL.md",
    ".agents/skills/xcx/SKILL.md",
    ".agents/skills/fh/SKILL.md",
    "knowledge_base/README.md",
]

# 引用形态：scripts/x.py、tools/…、prompts\x.md、根目录裸 xxx.py（限白名单动词开头避免误报）
ROOT_PY = re.compile(r"(?<![\w./\\-])([a-z_][a-z0-9_]*)\.py\b")
SCRIPTS_REF = re.compile(r"(?<![\w-])(scripts[\\/][A-Za-z0-9_\-./\\]+\.py)")
TOOLS_REF = re.compile(r"(?<![\w-])(tools[\\/][A-Za-z0-9_\-./\\]+\.(?:py|exe|bat|md|yaml))")
PROMPTS_REF = re.compile(r"prompts[\\/]([A-Za-z0-9_\-\\.]+\.md)")
KNOWN_ROOT = {p.name for p in list(ROOT.glob("*.py")) + list((ROOT / "labs").glob("*.py")) + list((ROOT / "scripts").glob("*.py"))}


def check() -> int:
    issues: list[str] = []
    for rel in DOCS:
        path = ROOT / rel
        if not path.is_file():
            issues.append(f"[缺文档] {rel}")
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for m in SCRIPTS_REF.finditer(text):
            ref = m.group(1).replace("\\", "/")
            # skill 文档的相对路径基准是文档自身目录（先查文档旁，再查仓库根）
            if not ((path.parent / ref).is_file() or (ROOT / ref).is_file()):
                issues.append(f"[漂移] {rel} 引用 {m.group(1)} 不存在")
        if rel != "AGENT_MANIFEST.md":  # MANIFEST 是机器生成的外置工具清单，未安装≠漂移
            for m in TOOLS_REF.finditer(text):
                ref = m.group(1).replace("\\", "/")
                if not (ROOT / ref).exists():
                    issues.append(f"[漂移] {rel} 引用 {m.group(1)} 不存在")
        for m in PROMPTS_REF.finditer(text):
            if not (ROOT / "prompts" / m.group(1)).is_file():
                issues.append(f"[漂移] {rel} 引用 prompts/{m.group(1)} 不存在")
        for m in ROOT_PY.finditer(text):
            name = f"{m.group(1)}.py"
            if name in KNOWN_ROOT:
                continue  # 存在
            # 只报"看起来像本仓库工具名"的：出现在反引号或命令上下文里
            ctx = text[max(0, m.start() - 40):m.end() + 10]
            if "`" in ctx or "python" in ctx.lower():
                issues.append(f"[疑似] {rel} 提到 {name}（根目录不存在；若为外部工具请忽略）")
    if issues:
        print(f"[!] 发现 {len(issues)} 处文档漂移：")
        for i in issues:
            print("   ", i)
        return 1
    print("[+] 无文档漂移：所有被引用路径均存在")
    return 0


if __name__ == "__main__":
    sys.exit(check())
