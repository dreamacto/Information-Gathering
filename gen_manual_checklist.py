#!/usr/bin/env python3
# encoding: utf-8
"""
手动测试清单生成器（Phase 4f — 文件上传 / 认证绕过 / 敏感功能）
  从前面阶段的结果中提取需要手动测试的 URL，生成详细清单。
  - 文件上传点：列出来源页面和具体 URL
  - 登录/认证入口：列出 SSO / 表单 / 扫码等类型
  - 后台管理入口：列出 admin/manager 等已发现的目录
  - 危险参数：列出高风险 GET 参数

  点击运行后自动读取 {project}/ 目录下的已有产出，整合成一份清单。

用法:
  python gen_manual_checklist.py --project glut
"""

import argparse
import re
import sys
import time
from urllib.parse import urljoin, urlparse

from pentest_utils import resolve_path, BASE_DIR


def read_urls(path):
    urls = []
    if not os.path.isfile(path):
        return urls
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            match = re.search(r"https?://\S+", line)
            if match:
                urls.append(match.group(0).rstrip(")"))
    return urls


def extract_upload_urls(project):
    """从 dirs.txt 中提取与上传/文件相关的 URL"""
    urls = set()
    fpath = resolve_path(project, "dirs.txt")
    if not os.path.isfile(fpath):
        return urls
    keywords = ["upload", "file", "upfile", "down", "download", "import", "export",
                "attach", "attachment", "media", "image", "img", "editor", "ueditor",
                "ckeditor", "kindeditor", "fckeditor", "uploadify", "uploadfile"]
    with open(fpath, "r", encoding="utf-8") as f:
        for line in f:
            lower = line.lower()
            if any(k in lower for k in keywords):
                match = re.search(r"https?://\S+", line)
                if match:
                    urls.add(match.group(0).rstrip(")"))
    return sorted(urls)


def extract_admin_urls(project):
    """从 dirs.txt 中提取管理后台"""
    urls = set()
    fpath = resolve_path(project, "dirs.txt")
    if not os.path.isfile(fpath):
        return urls
    keywords = ["admin", "manage", "manager", "root", "panel", "cp", "control",
                "system", "sys", "config", "setup", "install", "dashboard"]
    with open(fpath, "r", encoding="utf-8") as f:
        for line in f:
            lower = line.lower()
            if any(f"/{k}" in lower or f"/{k}/" in lower for k in keywords):
                match = re.search(r"https?://\S+", line)
                if match:
                    urls.add(match.group(0).rstrip(")"))
    return sorted(urls)


def extract_login_urls(project):
    """从 dirs.txt 中提取登录相关 URL"""
    urls = set()
    fpath = resolve_path(project, "dirs.txt")
    if not os.path.isfile(fpath):
        return urls
    keywords = ["login", "signin", "logon", "auth", "sso", "cas", "oauth",
                "passport", "verify"]
    with open(fpath, "r", encoding="utf-8") as f:
        for line in f:
            lower = line.lower()
            if any(f"/{k}" in lower or f"/{k}/" in lower for k in keywords):
                match = re.search(r"https?://\S+", line)
                if match:
                    urls.add(match.group(0).rstrip(")"))
    return sorted(urls)


def generate_checklist(project):
    uploads = extract_upload_urls(project)
    admins = extract_admin_urls(project)
    logins = extract_login_urls(project)
    urls = read_urls(resolve_path(project, "urls.txt"))

    lines = []
    lines.append("#" * 70)
    lines.append(f"# 手动测试清单 - {project}")
    lines.append(f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("#" * 70)

    # ---------- 文件上传 ----------
    lines.append("\n" + "=" * 60)
    lines.append("一、文件上传漏洞测试（手动）")
    lines.append("=" * 60)
    lines.append("【风险】任意文件上传可导致 getshell")
    lines.append("【方法】尝试上传 .php/.jsp/.asp 等脚本文件，改后缀绕过，Content-Type 绕过\n")
    if uploads:
        lines.append(f"共发现 {len(uploads)} 个可疑上传/文件入口：\n")
        for u in uploads:
            lines.append(f"  - {u}")
            lines.append(f"    操作: 浏览器打开 → 找上传按钮 → 尝试上传 webshell")
            lines.append(f"    备注: 注意检查是否有 MIME 校验、后缀黑名单、文件头校验")
    else:
        lines.append("未从目录扫描中发现上传入口。")
        lines.append("建议手动检查主站点的文件上传功能（如 Avatar、附件、导入等）")
        lines.append(f"主站点列表:")
        for u in urls[:20]:
            lines.append(f"  - {u}")

    # ---------- 登录/认证 ----------
    lines.append("\n" + "=" * 60)
    lines.append("二、登录/认证入口测试（手动）")
    lines.append("=" * 60)
    lines.append("【风险】弱口令、暴力破解、未授权访问、SSO 绕过")
    lines.append("【方法】测试默认密码、万能密码、SQL注入绕过、逻辑缺陷\n")
    if logins:
        lines.append(f"共发现 {len(logins)} 个登录入口：\n")
        for u in logins:
            lines.append(f"  - {u}")
            lines.append(f"    操作: 浏览器打开 → 尝试 admin/admin, admin/123456, test/test")
            lines.append(f"          尝试万能密码: admin' OR '1'='1")
            lines.append(f"          查看页面源码是否有注释/默认账号")
    else:
        lines.append("未从目录扫描中发现登录入口。")

    # ---------- 后台管理 ----------
    lines.append("\n" + "=" * 60)
    lines.append("三、后台管理入口（手动探索）")
    lines.append("=" * 60)
    lines.append("【风险】未授权访问后台、越权操作、信息泄露")
    lines.append("【方法】直接访问后台URL，尝试未授权进入\n")
    if admins:
        lines.append(f"共发现 {len(admins)} 个管理入口：\n")
        for u in admins:
            lines.append(f"  - {u}")
            lines.append(f"    操作: 浏览器直接访问，看是否跳转到登录页")
    else:
        lines.append("未从目录扫描中发现管理入口。")

    # ---------- 补充建议 ----------
    lines.append("\n" + "=" * 60)
    lines.append("四、其他手动测试建议")
    lines.append("=" * 60)
    lines.append("1. XSS: 先看 xss_manual_review.md / 04C_XSS反射候选队列；默认只用随机 marker 复核反射，不在留言板等写入位置全站发送脚本 payload")
    lines.append("2. CSRF: 检查表单是否有随机 token")
    lines.append("3. 越权: 修改 URL 中的 userid/orderid 参数查看他人数据")
    lines.append("4. 短信/邮件轰炸: 抓包重放验证码发送接口")
    lines.append("5. API 接口: 检查 /api/ 路径是否有未授权接口")
    lines.append("6. 源码泄露: 尝试 .git/HEAD, .svn/entries, .DS_Store, 网站备份 .rar/.zip/.7z")

    lines.append(f"\n\n扫描范围共 {len(urls)} 个主站点")
    for u in urls:
        lines.append(f"  {u}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="手动测试清单生成")
    parser.add_argument("--project", "--abbr", default=None, dest="project")
    args = parser.parse_args()

    project = args.project
    if not project:
        project = input("请输入项目缩写（如 glut、guat）: ").strip().lower()
        if not project:
            print("[-] 项目缩写不能为空")
            sys.exit(1)

    print("=" * 60)
    print(f"  手动测试清单生成 - [{project}]")
    print("=" * 60)

    checklist = generate_checklist(project)

    outpath = resolve_path(project, "upload_manual.txt")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(checklist)
    print(f"[√] 手动测试清单已生成: {outpath}")

    # 打印摘要
    uploads = extract_upload_urls(project)
    admins = extract_admin_urls(project)
    logins = extract_login_urls(project)
    print(f"\n摘要:")
    print(f"  文件上传入口: {len(uploads)} 个")
    print(f"  登录入口:     {len(logins)} 个")
    print(f"  管理后台:     {len(admins)} 个")
    print(f"\n请打开 {outpath} 逐项手动测试")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 已取消")
    except Exception as e:
        print(f"\n[!] 错误: {e}")
    input("\n按 Enter 退出...")
