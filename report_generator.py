#!/usr/bin/env python3
# encoding: utf-8
"""
综合报告生成器（Phase 5）
  读取所有阶段的产出文件，整合为一份综合 HTML 报告。

用法:
  python report_generator.py --project glut
"""

import argparse
import os
import re
import sys
import time
from datetime import datetime

from pentest_utils import resolve_path, BASE_DIR


def read_section(filepath, title):
    if not os.path.isfile(filepath):
        return f"<p style='color:#999'>(暂无数据 — 运行对应阶段后更新)</p>"
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    # 把纯文本转成 HTML
    escaped = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    escaped = re.sub(r"(https?://\S+)", r'<a href="\1" target="_blank">\1</a>', escaped)
    escaped = escaped.replace("\n", "<br>")
    return f"<pre style='white-space:pre-wrap; font-size:0.85em; background:#f9f9f9; padding:10px;'>{escaped}</pre>"


def generate_report(project):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    files = {
        "子域名收集": resolve_path(project, "urls.txt"),
        "信息收集报告": resolve_path(project, "report.html"),
        "目录爆破": resolve_path(project, "dirs.txt"),
        "SQL注入": resolve_path(project, "sqli.txt"),
        "目录遍历": resolve_path(project, "traversal.txt"),
        "SSTI模板注入": resolve_path(project, "ssti.txt"),
        "命令注入(RCE)": resolve_path(project, "rce.txt"),
        "文件包含(LFI)": resolve_path(project, "lfi.txt"),
        "手动测试清单": resolve_path(project, "upload_manual.txt"),
    }

    sections_html = ""
    for title, fpath in files.items():
        safe_title = title.replace(" ", "_")
        exists = os.path.isfile(fpath)
        icon = "✅" if exists else "⏳"
        sections_html += f"""
        <div class='section'>
          <h2>{icon} {title}</h2>
          {read_section(fpath, title)}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<title>渗透测试综合报告 - {project}</title>
<style>
  body {{ font-family:'Segoe UI',Tahoma,sans-serif; margin:20px; background:#f5f5f5; }}
  h1 {{ color:#222; border-bottom:3px solid #005a9e; padding-bottom:10px; }}
  .section {{ background:#fff; margin:15px 0; padding:15px; border-radius:6px; box-shadow:0 1px 3px rgba(0,0,0,0.1); }}
  .section h2 {{ margin-top:0; font-size:1.1em; color:#005a9e; }}
  .summary {{ background:#005a9e; color:#fff; padding:15px; border-radius:6px; margin-bottom:20px; }}
  .summary table {{ width:100%; color:#fff; }}
  .summary td {{ padding:5px 10px; }}
  pre {{ white-space:pre-wrap; word-break:break-all; }}
  a {{ color:#005a9e; }}
  .danger {{ background:#fff3e0; padding:3px 8px; border-radius:3px; color:#b71c1c; font-weight:bold; }}
  .footer {{ text-align:center; color:#999; font-size:0.8em; margin-top:30px; }}
</style>
</head>
<body>
<h1>渗透测试综合报告</h1>
<div class="summary">
  <table>
    <tr><td>项目:</td><td><strong>{project}</strong></td></tr>
    <tr><td>生成时间:</td><td>{now}</td></tr>
    <tr><td>数据目录:</td><td>{project}/</td></tr>
  </table>
</div>
{sections_html}
<div class='footer'>仅供授权安全测试使用</div>
</body>
</html>"""

    outpath = resolve_path(project, "final_report.html")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[√] 综合报告已生成: {outpath}")


def main():
    parser = argparse.ArgumentParser(description="综合报告生成")
    parser.add_argument("--project", "--abbr", default=None, dest="project")
    args = parser.parse_args()

    project = args.project
    if not project:
        project = input("请输入项目缩写（如 glut、guat）: ").strip().lower()
        if not project:
            print("[-] 项目缩写不能为空")
            sys.exit(1)

    print("=" * 60)
    print(f"  综合报告生成 - [{project}]")
    print("=" * 60)
    generate_report(project)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 已取消")
    except Exception as e:
        print(f"\n[!] 错误: {e}")
    input("\n按 Enter 退出...")
