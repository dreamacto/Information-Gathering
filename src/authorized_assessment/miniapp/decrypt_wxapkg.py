#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""decrypt_wxapkg.py —— 微信小程序加密包解密 + 快速线索提取（20260823 重构为可复用 CLI）。

原来是一次性脚本（硬编码 AppID/路径），现改为参数化；算法不变：
  V1MMWX 头(6B) → 前 1024B 对齐块 AES-CBC 解密（PBKDF2(appid,"saltiest",1000,32) 定长 IV）
  → 其余字节 XOR 候选 [appid[-2], appid[-1], 0x66, 0x00] 取可打印率最高者。
无 V1MMWX 头的包视为已解密，直接透传（只做线索提取，不动字节）。

用法（必须 .venv 运行时，含 cryptography）：
  .venv/Scripts/python.exe decrypt_wxapkg.py --appid wx1234567890abcdef A.wxapkg B.wxapkg
  .venv/Scripts/python.exe decrypt_wxapkg.py --appid wx... --dir <包目录> --out <输出目录>

输出：
  <out>/<名>.decrypted.wxapkg     解密后的包（可继续喂 full_unpack_wxapkg.py 还原源码）
  <out>/decrypt_report.md/.jsonl  URL/域名提取报告（已滤微信/腾讯系噪声）

完整源码还原用 full_unpack_wxapkg.py <appid> <包路径> <输出目录>（.venv，pycryptodome）。
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import argparse
import hashlib
import json
import re
import struct
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CST = timezone(timedelta(hours=8))
NOISE = ['servicewechat', 'qq.com', 'weixin', 'qpic.cn', 'gtimg.cn', 'wxgateway', 'tencent.com',
         'wechat.com', 'apple.com', 'w3.org', 'xweb', 'json.org', 'wx.qq.com', 'msdk', 'bugly',
         'qcloud.com', 'github.com', 'schema.org', 'googleapis', 'whatwg', 'ecma', 'w3c']


def now_iso() -> str:
    return datetime.now(CST).isoformat(timespec="seconds")


def pbkdf2_key(appid: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", appid.encode("utf-8"), b"saltiest", 1000, dklen=32)


def aes_cbc_decrypt(block: bytes, appid: str) -> bytes:
    key = pbkdf2_key(appid)
    iv = b"the iv: 16 bytes"
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    return decryptor.update(block) + decryptor.finalize()


def printable_ratio(data: bytes, sample: int = 20000) -> float:
    s = data[:sample]
    if not s:
        return 0.0
    n = sum(1 for b in s if 0x20 <= b < 0x7f or b in (0x0a, 0x0d, 0x09))
    return n / len(s)


def wxapkg_index_score(data: bytes) -> int:
    """结构化选键打分：能连续通过结构校验的索引条目数（0 = 头不合法/立即失败）。

    可打印率启发式不可靠：JSON/压缩 JS 文本 XOR 0x5F 后大多仍可打印，而正确键的
    解码含索引区二进制 offset/size 字段反而拉低得分——曾导致主包选错 XOR 键。
    """
    ok = 0
    try:
        if len(data) < 22 or data[0] != 0xBE or data[13] != 0xED:
            return 0
        pos = 14
        count = struct.unpack(">I", data[pos:pos + 4])[0]
        pos += 4
        if not (0 < count <= 100000):
            return 0
        for _ in range(count):
            nl = struct.unpack(">I", data[pos:pos + 4])[0]
            pos += 4
            if not (0 < nl < 4096):
                break
            data[pos:pos + nl].decode("utf-8")
            pos += nl
            off = struct.unpack(">I", data[pos:pos + 4])[0]
            sz = struct.unpack(">I", data[pos + 4:pos + 8])[0]
            pos += 8
            if off + sz > len(data):
                break
            ok += 1
    except Exception:
        pass
    return ok


def decrypt_package(raw: bytes, appid: str) -> tuple[bytes, str, bool]:
    """返回 (明文, 采用的XOR键说明, 是否加密包)。无 V1MMWX 头视为已解密直接透传。"""
    if raw[:6] != b"V1MMWX":
        return raw, "plain(无V1MMWX头,透传)", False
    body = raw[6:]
    first_len = min(1024, len(body))
    first_len -= first_len % 16
    if first_len <= 0:
        return body, "too_short", True
    first = aes_cbc_decrypt(body[:first_len], appid)
    # 加密方对前 first_len-1 字节做 PKCS7 填充后整块加密：解密结果末尾是填充字节，
    # 必须剥离；XOR 区从 body[first_len] 起（body[first_len-1] 只是填充的密文载体）。
    # 不剥离会导致尾部明文整体错位 1 字节（索引/文件内容全损）。
    pad = first[-1]
    if 1 <= pad <= 16 and first[-pad:] == bytes([pad]) * pad:
        first = first[:-pad]
    rest = body[first_len:]
    best, best_ratio, best_key, best_score = None, -1.0, None, -1
    for xor_key in [ord(appid[-2]), ord(appid[-1]), 0x66, 0x00]:
        decoded_rest = rest if xor_key == 0 else bytes(b ^ xor_key for b in rest)
        decoded = first + decoded_rest
        score = wxapkg_index_score(decoded)
        ratio = printable_ratio(decoded)
        if score > best_score or (score == best_score and ratio > best_ratio):
            best, best_ratio, best_key, best_score = decoded, ratio, xor_key, score
    return best, f"XOR_{best_key:02x}(index={best_score},printable={best_ratio:.1%})", True


def extract_leads(data: bytes) -> tuple[list[str], list[str]]:
    urls = set()
    for m in re.finditer(rb"https?://[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9][-a-zA-Z0-9./_?=&%#:@+]*", data):
        url = m.group().decode("ascii", errors="replace")
        if len(url) > 20:
            urls.add(url.rstrip(".,;)\"'<>\\"))
    domains = set()
    for m in re.finditer(rb"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?", data):
        d = m.group().decode("ascii", errors="replace").lower()
        if len(d) > 6 and "." in d and not d[0].isdigit():
            domains.add(d)
    clean_urls = sorted(u for u in urls if not any(n in u.lower() for n in NOISE))
    clean_doms = sorted(d for d in domains if not any(n in d for n in NOISE))
    return clean_urls, clean_doms


def main() -> int:
    ap = argparse.ArgumentParser(description="wxapkg 解密+快速线索提取（可复用 CLI；完整源码还原用 full_unpack_wxapkg.py）")
    ap.add_argument("packages", nargs="*", type=Path, help=".wxapkg 文件（可多个）")
    ap.add_argument("--appid", required=True, help="小程序 AppID（解密密钥派生源）")
    ap.add_argument("--dir", type=Path, default=None, help="扫描目录下全部 *.wxapkg（与文件参数可并用）")
    ap.add_argument("--out", type=Path, default=None, help="输出目录（默认 <第一个输入所在目录>/decrypted）")
    a = ap.parse_args()

    files: list[Path] = list(a.packages)
    if a.dir:
        files += sorted(p for p in a.dir.rglob("*.wxapkg"))
    files = [f for f in files if f.is_file()]
    if not files:
        print("[!] 未找到任何 .wxapkg（给文件参数或 --dir）")
        return 2

    out = a.out or (files[0].parent / "decrypted")
    out.mkdir(parents=True, exist_ok=True)

    all_rows: list[dict] = []
    all_data = b""
    ok = 0
    for pkg in files:
        raw = pkg.read_bytes()
        plain, method, was_encrypted = decrypt_package(raw, a.appid)
        dest = out / (pkg.stem + ".decrypted.wxapkg")
        dest.write_bytes(plain)
        ratio = printable_ratio(plain)
        urls, domains = extract_leads(plain)
        row = {
            "ts": now_iso(), "appid": a.appid, "package": str(pkg), "decrypted_path": str(dest),
            "was_encrypted": was_encrypted, "method": method, "size": len(plain),
            "printable_ratio": round(ratio, 3), "urls": urls, "domains": domains,
        }
        all_rows.append(row)
        all_data += plain
        ok += 1
        print(f"[+] {pkg.name} -> {dest.name} | {method} | {len(plain)}B | 线索: {len(urls)} URL / {len(domains)} 域")

    urls, domains = extract_leads(all_data)
    md = out / "decrypt_report.md"
    lines = [f"# wxapkg 解密线索报告 · {now_iso()}",
             f"- appid: `{a.appid}` · 包 {ok} 个 · 输出: `{out}`", "",
             "## 非微信系 URL（进 host 分类，未确认归属前不打）", ""]
    lines += [f"- {u}" for u in urls] or ["- （无）"]
    lines += ["", "## 非微信系域名", ""]
    lines += [f"- {d}" for d in domains] or ["- （无）"]
    md.write_text("\n".join(lines), encoding="utf-8")
    with (out / "decrypt_report.jsonl").open("w", encoding="utf-8") as f:
        for r in all_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[+] 报告 → {md}")
    print("[i] 下一步：python full_unpack_wxapkg.py <appid> <decrypted.wxapkg> <unpacked输出目录>（.venv）还原源码")
    return 0


if __name__ == "__main__":
    sys.exit(main())
