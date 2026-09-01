"""Compatibility entrypoint for the WMPF variant wxapkg unpacker.

真身：tools/miniapp_extract/unpack_wmpf_wxapkg.py
背景：decrypt_wxapkg.py/full_unpack_wxapkg.py 的标准实现对 PC 微信 4.x（WMPF）
变体包失败——AES 首块含 1 字节 PKCS#7 填充致索引错位 1B，且剩余区 XOR 键为
ord(appid[-2]) 而非 0x66。本工具按索引结构有效性选键，兼容两种方案。
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path

if __name__ == "__main__":
    _real = Path(__file__).resolve().parent / "tools" / "miniapp_extract" / "unpack_wmpf_wxapkg.py"
    sys.argv[0] = str(_real)
    runpy.run_path(str(_real), run_name="__main__")
