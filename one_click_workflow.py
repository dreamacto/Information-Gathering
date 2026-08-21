from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def setup_console() -> None:
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="One-click authorized exercise workflow launcher")
    parser.add_argument("--targets", type=Path, required=True, help="目标文件路径；一行一个 URL/域名，支持 url|单位名")
    parser.add_argument(
        "--mode",
        choices=["full", "subdomains"],
        default="full",
        help="full=完整流程；subdomains=已有子域名后的剩余流程",
    )
    parser.add_argument("--delay", type=float, default=3.0, help="请求间隔秒数")
    parser.add_argument("--limit", type=int, default=0, help="限制目标数量，0 表示不限制")
    parser.add_argument("--weak-max-targets", type=int, default=10, help="弱口令复核最多登录入口数")
    parser.add_argument("--weak-max-pairs", type=int, default=5, help="每个入口最多弱口令组合数")
    parser.add_argument("--sqli-limit", type=int, default=50, help="SQLi 低影响线索最多探测次数")
    parser.add_argument("--header-sqli-limit", type=int, default=20, help="Header 回显探测（UA/Referer/XFF/Origin/Cookie）最多 URL 数")
    parser.add_argument("--header-sqli-login-data", default=None,
                        help="URL 编码的登录表单数据；探测时以 POST 登录请求携带 marker Header，覆盖登录请求内注入场景")
    parser.add_argument("--xss-limit", type=int, default=80, help="XSS 候选最多处理参数数")
    parser.add_argument("--shiro-limit", type=int, default=30, help="Shiro 线索最多探测种子数")
    parser.add_argument("--second-pass-sql-limit", type=int, default=10, help="二次复测 SQLi 候选上限")
    parser.add_argument("--second-pass-xss-limit", type=int, default=20, help="二次复测 XSS 候选上限")
    parser.add_argument("--second-pass-api-limit", type=int, default=20, help="二次复测 API 候选上限")
    parser.add_argument("--no-weak", action="store_true", help="跳过弱口令显式复核")
    parser.add_argument("--no-xss", action="store_true", help="跳过 XSS 安全反射检查")
    parser.add_argument("--no-second-pass", action="store_true", help="跳过二次轻量复测")
    parser.add_argument("--no-review-intelligence", action="store_true", help="跳过离线 P0-P3 总表和目标画像")
    parser.add_argument("--fingerprint-deepening", action="store_true", default=False, help=argparse.SUPPRESS)
    parser.add_argument("--no-fingerprint-deepening", action="store_true", help="跳过指纹识别后的深入分支计划")
    parser.add_argument("--no-subdomain", action="store_true", help="完整流程中跳过低速子域名发现")
    parser.add_argument("--no-tool-fingerprint", action="store_true", help="跳过 httpx 工具指纹增强")
    parser.add_argument("--no-katana", action="store_true", help="跳过 Katana 受控爬取增强")
    parser.add_argument("--miniapp-search-pack", action="store_true", help="生成小程序人工搜索关键词包")
    return parser.parse_args()


def runner_command(args: argparse.Namespace) -> list[str]:
    label = "one_click_full_weak" if args.mode == "full" else "one_click_subdomains"
    cmd = [
        sys.executable,
        str(BASE_DIR / "gov_exercise_runner.py"),
        "--targets",
        str(args.targets),
        "--label",
        label,
        "--probe",
        "--fingerprint",
        "--high-value-paths",
        "--api-discovery",
        "--api-confirm",
        "--sqli-triage",
        "--sqli-limit",
        str(args.sqli_limit),
        "--header-sqli-triage",
        "--header-sqli-limit",
        str(args.header_sqli_limit),
        "--shiro-triage",
        "--shiro-limit",
        str(args.shiro_limit),
        "--idor-triage",
        "--delay",
        str(args.delay),
    ]
    if args.header_sqli_login_data:
        cmd.extend(["--header-sqli-login-data", args.header_sqli_login_data])
    if args.no_review_intelligence:
        cmd.append("--no-review-intelligence")
    else:
        cmd.append("--review-intelligence")
    if args.no_fingerprint_deepening:
        cmd.append("--no-fingerprint-deepening")
    if args.mode == "full" and not args.no_subdomain:
        cmd.extend([
            "--subdomain-bruteforce",
            "--subdomain-delay",
            str(max(1.5, args.delay)),
        ])
    if not args.no_tool_fingerprint:
        cmd.append("--tool-fingerprint")
    if not args.no_katana:
        cmd.append("--api-use-katana")
    if not args.no_xss:
        cmd.extend([
            "--xss-triage",
            "--xss-reflect-check",
            "--xss-limit",
            str(args.xss_limit),
            "--xss-max-per-host",
            "3",
        ])
    if args.limit:
        cmd.extend(["--limit", str(args.limit)])
    if not args.no_second_pass:
        cmd.extend([
            "--second-pass-triage",
            "--second-pass-sql-limit",
            str(args.second_pass_sql_limit),
            "--second-pass-xss-limit",
            str(args.second_pass_xss_limit),
            "--second-pass-api-limit",
            str(args.second_pass_api_limit),
        ])
    if not args.no_weak:
        cmd.extend([
            "--weak-credential-review",
            "--weak-credential-max-targets",
            str(args.weak_max_targets),
            "--weak-credential-max-pairs",
            str(args.weak_max_pairs),
        ])
    if args.miniapp_search_pack:
        cmd.append("--miniapp-search-pack")
    return cmd


def main() -> int:
    setup_console()
    args = parse_args()
    targets = args.targets.expanduser().resolve()
    if not targets.exists():
        print(f"[!] 目标文件不存在: {targets}", file=sys.stderr)
        return 2
    if not targets.is_file():
        print(f"[!] 目标路径不是文件: {targets}", file=sys.stderr)
        return 2
    args.targets = targets

    print("[*] 启动授权演练一键流程")
    print(f"[*] 模式: {args.mode}")
    print(f"[*] 目标文件: {targets}")
    print("[*] 弱口令复核:", "跳过" if args.no_weak else f"启用，最多 {args.weak_max_targets} 个入口，每个 {args.weak_max_pairs} 组")
    print(
        "[*] 子域名发现:",
        "跳过"
        if args.no_subdomain or args.mode != "full"
        else "完整流程启用，以输入主机为作用域锚点，禁止上提注册根域或扩展兄弟主机",
    )
    print("[*] 工具指纹:", "跳过" if args.no_tool_fingerprint else "启用 httpx 受控指纹")
    print("[*] Katana:", "跳过" if args.no_katana else "启用受控同站爬取增强")
    print("[*] XSS:", "跳过" if args.no_xss else f"启用安全 GET 标记反射检查，最多 {args.xss_limit} 个参数")
    print(
        "[*] 二次复测:",
        "跳过"
        if args.no_second_pass
        else f"启用轻量复测 SQLi {args.second_pass_sql_limit} / XSS {args.second_pass_xss_limit} / API {args.second_pass_api_limit}",
    )
    print("[*] P0-P3 总表/目标画像:", "跳过" if args.no_review_intelligence else "启用离线汇总")
    print("[*] 指纹后深入分支:", "跳过" if args.no_fingerprint_deepening else "启用离线工具/模板/审批队列")
    print("[*] 小程序自动发现: 不跑旧的网页线索发现；如需关键词包请使用 --miniapp-search-pack")
    print("")

    cmd = runner_command(args)
    proc = subprocess.Popen(
        cmd,
        cwd=BASE_DIR,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    collected_output: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        collected_output.append(line)
        print(line, end="", flush=True)
    proc.wait()
    if proc.returncode != 0:
        print(f"[!] 流程失败，returncode={proc.returncode}", file=sys.stderr)
        return proc.returncode

    run_dir = ""
    try:
        output_text = "".join(collected_output).strip()
        data = json.loads(output_text[output_text.rfind("{"):])
        run_dir = str(data.get("run_dir") or "")
    except Exception:
        pass
    if run_dir:
        last = BASE_DIR / "runs" / "last_one_click_run.txt"
        last.parent.mkdir(parents=True, exist_ok=True)
        last.write_text(run_dir + "\n", encoding="utf-8")
        print(f"[*] 本轮输出目录: {run_dir}")
        print(f"[*] 先看: {Path(run_dir) / '00_重要_人工复核入口' / 'README_先看这里.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
