# -*- coding: utf-8 -*-
"""
完整解包微信小程序：解密 V1MMWX 加密包 + 解析 wxapkg 结构，还原源码文件。
用法：
  python full_unpack_wxapkg.py <appid> <wxapkg路径> <输出目录>
"""
import hashlib, struct, sys, os
from Crypto.Cipher import AES

def pbkdf2_key(appid):
    return hashlib.pbkdf2_hmac("sha1", appid.encode("utf-8"), b"saltiest", 1000, dklen=32)

def decrypt_wxapkg(raw, appid):
    """解密 V1MMWX 格式的加密包，返回解密后的明文字节。"""
    if raw[:6] == b"V1MMWX":
        body = raw[6:]
    else:
        body = raw  # 未加密
    if len(body) < 1024:
        return body

    key = pbkdf2_key(appid)
    iv = b"the iv: 16 bytes"
    first_len = min(1024, len(body))
    first_len -= first_len % 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    first = cipher.decrypt(body[:first_len])
    rest = body[first_len:]

    # 4个XOR key选可打印率最高的
    best = None
    best_score = -1
    for xor_key in [ord(appid[-2]), ord(appid[-1]), 0x66, 0x00]:
        decoded = first + bytes(b ^ xor_key for b in rest)
        # 打分：可打印字符比例 + API关键词命中
        sample = decoded[:20000]
        printable = sum(1 for b in sample if 0x20 <= b < 0x7f or b in (0x0a, 0x0d, 0x09))
        score = printable / len(sample)
        if score > best_score:
            best_score = score
            best = decoded
    return best if best is not None else body

def parse_wxapkg(data):
    """解析 wxapkg 结构，返回 {文件名: 文件内容}。
    结构: 0xBE + unknownInfo(4) + infoListLength(4) + dataListLength(4) + 0xED + fileCount(4) + 文件索引"""
    files = {}
    if len(data) < 20:
        return files
    try:
        pos = 0
        if data[pos] == 0xBE:
            pos = 1
        # 跳过 unknownInfo(4) + infoListLength(4) + dataListLength(4)
        pos += 4 + 4 + 4
        # 0xED 标记
        if data[pos] == 0xED:
            pos += 1
        count = struct.unpack(">I", data[pos:pos+4])[0]
        pos += 4
        if count > 100000:
            return {}
        for _ in range(count):
            name_len = struct.unpack(">I", data[pos:pos+4])[0]
            pos += 4
            name = data[pos:pos+name_len].decode("utf-8", errors="replace")
            pos += name_len
            offset = struct.unpack(">I", data[pos:pos+4])[0]
            pos += 4
            size = struct.unpack(">I", data[pos:pos+4])[0]
            pos += 4
            if offset + size <= len(data):
                files[name] = data[offset:offset+size]
    except Exception as e:
        pass
    return files

def main():
    if len(sys.argv) < 4:
        print("用法: python full_unpack_wxapkg.py <appid> <wxapkg路径> <输出目录>")
        sys.exit(1)
    appid, pkg_path, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(pkg_path, "rb") as f:
        raw = f.read()

    decrypted = decrypt_wxapkg(raw, appid)
    print(f"[*] 包大小: {len(raw)} 字节, 解密后: {len(decrypted)} 字节")

    files = parse_wxapkg(decrypted)
    print(f"[*] 解析出 {len(files)} 个文件")

    os.makedirs(out_dir, exist_ok=True)
    for name, content in files.items():
        # 去掉路径穿越风险
        safe_name = name.replace("\\", "/").lstrip("/")
        full = os.path.join(out_dir, safe_name)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(content)

    # 如果解析失败，把解密后的原始包也存一份
    if not files:
        dump_path = os.path.join(out_dir, "__decrypted_raw__.bin")
        with open(dump_path, "wb") as f:
            f.write(decrypted)
        print(f"[!] 结构化解析失败，已存原始解密数据到 {dump_path}")

    # 打印文件清单
    print("\n=== 文件清单 ===")
    for name in sorted(files.keys()):
        print(f"  {name} ({len(files[name])} 字节)")

if __name__ == "__main__":
    main()
