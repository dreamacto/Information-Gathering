#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""report_docx.py —— 攻防成果报告 docx 生成器（2026-08-23，格式参考北港网报告）。

项目所有对外报告出口统一走本工具（替代手写 .md 成果报告）：
  1. 正式生成：AI 会话在 reporting 阶段先落 findings.json + meta.json（凭证纪律：
     命令里的 TOKEN 写 <见本地 sessions 文件>，真实凭证不进报告），再调本工具渲染 docx。
  2. 骨架模式（--from-ledger）：从 engagement 台账 confirmed 行直接生成带 TODO 标记的
     初稿，会话/人工补复现命令后重跑。
  3. 模板（--demo）：重新生成空白模板（templates/ 与桌面同步用）。

截图纪律：每个成果自动插入红色【需截图 S-N】占位——补齐截图前报告视为未完成。
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from docx import Document
from docx.shared import Pt, RGBColor
from docx.oxml.ns import qn

CST = timezone(timedelta(hours=8))
ROOT = Path(__file__).resolve().parent
RED = RGBColor(0xC0, 0x00, 0x00)
GRAY = RGBColor(0x80, 0x80, 0x80)


def now_date() -> str:
    return datetime.now(CST).strftime("%Y-%m-%d")


def _setup_styles(doc: Document) -> None:
    normal = doc.styles["Normal"]
    normal.font.name = "Arial"
    normal.font.size = Pt(10.5)
    normal.element.rPr.rFonts.set(qn("w:eastAsia"), "宋体")
    for i, sz in ((1, 16), (2, 13)):
        h = doc.styles[f"Heading {i}"]
        h.font.name = "Arial"
        h.font.size = Pt(sz)
        h.font.bold = True
        h.element.rPr.rFonts.set(qn("w:eastAsia"), "黑体")


def para(doc, text, bold=False, mono=False, size=None, color=None, italic=False):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.bold = bold
    r.italic = italic
    if mono:
        r.font.name = "Consolas"
        r.font.size = Pt(size or 9.5)
        r._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
    elif size:
        r.font.size = Pt(size)
    if color is not None:
        r.font.color.rgb = color
    return p


def shot_marker(doc, text):
    return para(doc, f"【需截图 {text}】", bold=True, color=RED)


def kv_table(doc, rows):
    t = doc.add_table(rows=0, cols=2)
    t.style = "Table Grid"
    for k, v in rows:
        cells = t.add_row().cells
        cells[0].text = k
        cells[1].text = v
        if cells[0].paragraphs[0].runs:
            cells[0].paragraphs[0].runs[0].bold = True
    return t


def build_report(meta: dict, findings: list[dict], out: Path) -> Path:
    doc = Document()
    _setup_styles(doc)

    para(doc, f"{meta.get('target_name', '{{目标名称}}')}（{meta.get('domains', '{{主域名}}')}）攻防成果报告",
         bold=True, size=16)
    shot_marker(doc, "S-0：报告首页不需要截图；下列红色【需截图】处必须全部补齐后报告才算完成")

    # 一、综述
    doc.add_heading("一、综述", level=1)
    para(doc, meta.get(
        "intro",
        "{{测试起日}}至{{测试止日}}，对{{目标名称}}（{{域名列表}}）进行授权渗透测试。"
        "{{目标一句话业务定位与技术栈}}。测试在授权范围内进行，全程低速只读优先，写操作经审批门确认。"))
    para(doc, "渗透成果汇总表", bold=True)
    t = doc.add_table(rows=1, cols=6)
    t.style = "Table Grid"
    for i, h in enumerate(["序号", "渗透对象", "漏洞类型", "URL/端点", "影响范围", "风险等级"]):
        c = t.rows[0].cells[i]
        c.text = h
        if c.paragraphs[0].runs:
            c.paragraphs[0].runs[0].bold = True
    for n, f in enumerate(findings, 1):
        cells = t.add_row().cells
        cells[0].text = str(n)
        cells[1].text = f.get("system", "{{}}")
        cells[2].text = f.get("threat", "{{}}")
        cells[3].text = f.get("url", "{{}}")
        cells[4].text = f.get("data_volume", "{{}}")
        cells[5].text = f.get("level", "{{}}")
    para(doc, "渗透结果统计：" + meta.get("stats", "{{成果分项统计与总量}}"))

    # 二、渗透成果说明
    doc.add_heading("二、渗透成果说明", level=1)
    para(doc, "以下命令均在 Git Bash 中验证通过。每条命令均为单行，直接复制粘贴执行。"
              "所有命令先设置环境变量，后续依赖该 Token。")
    para(doc, "环境准备（先执行这几条）：", bold=True)
    for line in meta.get("env_lines", ['BASE="{{https://目标域名}}"',
                                       'TOKEN="{{登录后获取的凭证——真实值仅存本地 sessions 文件，报告内写 <见本地凭证文件>}}"']):
        para(doc, line, mono=True)

    for n, f in enumerate(findings, 1):
        doc.add_heading(f"成果{n}：{f.get('title', '{{量化标题}}')}", level=2)
        para(doc, "（1）基本情况表", bold=True)
        kv_table(doc, [
            ("序号", str(n)),
            ("成果描述", f.get("desc", "{{一句话：什么权限的账号能做什么，拿到多少什么数据}}")),
            ("目标系统", f.get("system", "{{目标名}} ({{域名}}) — {{技术栈}}")),
            ("目标URL", f.get("url", "{{GET/POST /api/xxx}}")),
            ("威胁类型", f.get("threat", "{{获取数据类 / 未授权访问 / 越权}}")),
            ("涉及数据量", f.get("data_volume", "{{N条}}")),
            ("风险等级", f.get("level", "{{严重/高危/中危/低危}}")),
            ("权限验证", f.get("perm_check", "{{验证所用账号及其正常权限范围，证明是越权}}")),
        ])
        para(doc, "（2）完整复现命令", bold=True)
        for cmd in f.get("commands", []):
            if isinstance(cmd, str):
                cmd = {"cmd": cmd}
            para(doc, cmd.get("cmd", "{{curl ...}}"), mono=True)
            if cmd.get("note"):
                para(doc, cmd["note"])
        if f.get("interpretation"):
            para(doc, "返回结果解读：" + f["interpretation"])
        shot_marker(doc, f"S-{n}：执行成果{n}主命令后的完整响应画面（需含 total/关键字段与系统时间，敏感值脱敏）")
        if f.get("pagination"):
            para(doc, "翻页验证（证明可遍历，修改 pageNo）：")
            for line in f["pagination"]:
                para(doc, line, mono=True)
            shot_marker(doc, f"S-{n}p：翻页后第2页响应（页码字段可见）")
        for ev in f.get("evidence", []):
            para(doc, f"证据：{ev}")
    if not findings:
        para(doc, "（无 confirmed 成果——按台账补 findings 或用 --from-ledletter 骨架模式）",
             italic=True, color=GRAY)

    # 三、存在问题 / 四、整改建议
    doc.add_heading("三、存在问题", level=1)
    for item in meta.get("problems", ["{{除已列成果外的安全观察，逐条列出}}"]):
        para(doc, item)
    doc.add_heading("四、整改建议", level=1)
    for i, item in enumerate(meta.get("suggestions", ["{{逐条对应成果给出整改措施}}", "{{总体建议}}"]), 1):
        para(doc, f"{i}. {item}")

    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(out)
    return out


PRIORITY_LEVEL = {"high": "高危", "medium": "中危", "low": "低危"}


def from_ledger(engagement: Path) -> tuple[dict, list[dict]]:
    """骨架模式：confirmed 行 → findings 骨架（命令/解读留 TODO 标记待补）。"""
    ledger = engagement / "review_ledger.csv"
    rows = []
    with ledger.open(encoding="utf-8-sig", newline="") as f:
        rows = [r for r in csv.DictReader(f) if (r.get("status") or "").strip() == "confirmed"]
    findings = []
    for r in rows:
        findings.append({
            "title": (r.get("summary") or r.get("category") or "待命名成果")[:80],
            "desc": r.get("summary", ""),
            "system": r.get("asset", ""),
            "url": (r.get("endpoint") or "") + (f"（参数: {r['parameter']}）" if r.get("parameter") else ""),
            "threat": r.get("category", ""),
            "data_volume": "TODO（补量化影响）",
            "level": PRIORITY_LEVEL.get((r.get("priority") or "").strip().lower(), "待定"),
            "perm_check": r.get("role") or "TODO（补权限验证说明）",
            "commands": [{"cmd": "TODO：补完整复现命令（参考 evidence/log 脚本与 validation_result）"}],
            "interpretation": "TODO：补 total/pages 换算与影响量化解读",
            "evidence": [r["evidence_ref"]] if r.get("evidence_ref") else [],
        })
    meta = {
        "target_name": engagement.name.rsplit("-", 1)[0] if "-" in engagement.name else engagement.name,
        "domains": engagement.name.rsplit("-", 1)[0] if "-" in engagement.name else "{{主域名}}",
        "intro": "TODO：补测试时间窗/授权说明/目标业务与技术栈。",
        "stats": f"TODO：共 {len(findings)} 项 confirmed 成果，补分项统计与总量。",
        "problems": ["TODO：补成果外安全观察。"],
        "suggestions": ["TODO：逐条对应成果补整改措施。"],
    }
    return meta, findings


def demo() -> tuple[dict, list]:
    meta = {
        "target_name": "{{目标名称}}",
        "domains": "{{主域名}}",
        "intro": ("{{测试起日}}至{{测试止日}}，对{{目标名称}}（{{域名列表}}）进行授权渗透测试。"
                  "{{目标一句话业务定位与技术栈}}。测试在授权范围内进行，全程低速只读优先，写操作经审批门确认。"),
        "stats": "{{获取数据类N项，涉及数据总量约N条（分项列举）}}",
        "problems": ["{{除已列成果外的安全观察：弱口令策略/验证码缺失/接口无频控/错误信息泄露等}}"],
        "suggestions": ["{{逐条对应成果：接口增加服务端对象级鉴权}}", "{{总体建议：最小权限/数据最小化/越权监控}}"],
    }
    findings = [{
        "title": "{{量化标题，如：全量用户数据泄露（NNN,NNN条）}}",
        "desc": "{{一句话：什么权限的账号能做什么，拿到多少什么数据}}",
        "system": "{{目标名}} ({{域名}}) — {{技术栈}}",
        "url": "{{GET/POST /api/xxx}}",
        "threat": "{{获取数据类 / 未授权访问 / 越权}}",
        "data_volume": "{{N条}}",
        "level": "{{严重/高危/中危/低危}}",
        "perm_check": "{{验证所用账号及其正常权限范围，证明是越权}}",
        "commands": [{"cmd": 'curl -s "$BASE/{{端点}}?pageNo=1&pageSize=10" -H "X-Access-Token: $TOKEN"{{其他头}}',
                      "note": "返回结果解读：total={{N}}，pages={{N}}，每页{{pageSize}}条，共 {{N×pages}} 条。"}],
        "pagination": [
            'curl -s "$BASE/{{端点}}?pageNo=1&pageSize=10" -H "X-Access-Token: $TOKEN"   # 第1页',
            'curl -s "$BASE/{{端点}}?pageNo=2&pageSize=10" -H "X-Access-Token: $TOKEN"   # 第2页',
            'curl -s "$BASE/{{端点}}?pageNo=3&pageSize=10" -H "X-Access-Token: $TOKEN"   # 第3页',
        ],
        "evidence": ["{{evidence/截图N-1.png：响应关键字段脱敏节选}}"],
    }]
    return meta, findings


def main() -> int:
    ap = argparse.ArgumentParser(description="攻防成果报告 docx 生成器（北港网格式 + 自动截图标注）")
    ap.add_argument("--meta", type=Path, help="meta.json（综述/统计/问题/建议）")
    ap.add_argument("--findings", type=Path, help="findings.json（成果数组：标题/描述/命令/翻页/证据）")
    ap.add_argument("--from-ledger", type=Path, help="engagement 目录：从台账 confirmed 行生成骨架初稿")
    ap.add_argument("--demo", action="store_true", help="重新生成空白模板")
    ap.add_argument("--out", type=Path, help="输出 docx 路径")
    a = ap.parse_args()

    if a.demo:
        meta, findings = demo()
        out = a.out or (ROOT / "templates" / "攻防成果报告_模板.docx")
    elif a.from_ledger:
        meta, findings = from_ledger(a.from_ledger)
        name = a.from_ledger.name
        out = a.out or (a.from_ledger / "reports" / f"攻防成果报告_{name}_{now_date()}.docx")
    elif a.meta and a.findings:
        meta = json.loads(a.meta.read_text(encoding="utf-8"))
        findings = json.loads(a.findings.read_text(encoding="utf-8"))
        out = a.out or (ROOT / f"攻防成果报告_{meta.get('target_name', 'report')}_{now_date()}.docx")
    else:
        ap.error("需要 --demo / --from-ledger / (--meta + --findings) 三者之一")

    path = build_report(meta, findings, out)
    n_shots = 1 + sum(1 + (1 if f.get("pagination") else 0) for f in findings)
    print(f"[+] 报告 → {path}")
    print(f"[+] 成果 {len(findings)} 项；含 {n_shots} 处红色【需截图】标注——补齐截图前报告视为未完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
