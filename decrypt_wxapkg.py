import hashlib, re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pbkdf2_key(appid):
    return hashlib.pbkdf2_hmac("sha1", appid.encode("utf-8"), b"saltiest", 1000, dklen=32)

def aes_cbc_decrypt_1024(block, appid):
    key = pbkdf2_key(appid)
    iv = b"the iv: 16 bytes"
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    return decryptor.update(block) + decryptor.finalize()

appid = "wx46eb1076af120bc3"
base = "C:/Users/ASUS/AppData/Roaming/Tencent/xwechat/radium/users/64a7b1dae792358764749c820add44b9/applet/packages/wx46eb1076af120bc3/37"

all_data = b""
for fname in ["__APP__.wxapkg", "_pages_home_sub_.wxapkg"]:
    with open(f"{base}/{fname}", "rb") as f:
        raw = f.read()

    body = raw[6:]
    first_len = min(1024, len(body))
    first_len -= first_len % 16
    if first_len <= 0:
        continue
    first = aes_cbc_decrypt_1024(body[:first_len], appid)
    rest = body[first_len:]

    for xor_key in [ord(appid[-2]), ord(appid[-1]), 0x66, 0x00]:
        decoded_rest = rest if xor_key == 0 else bytes(b ^ xor_key for b in rest)
        decoded = first + decoded_rest
        printable = sum(1 for b in decoded[:10000] if 0x20 <= b < 0x7f or b in (0x0a, 0x0d, 0x09))
        ratio = printable / min(10000, len(decoded))
        if ratio > 0.15:
            print(f"  {fname} XOR_{xor_key:02x}: {len(decoded)} bytes, printable ratio={ratio:.2%}")
            all_data += decoded
            break

print(f"\nTotal decrypted: {len(all_data)} bytes")

# Extract URLs
noise = ['servicewechat','qq.com','weixin','qpic.cn','gtimg.cn','wxgateway','tencent.com',
         'wechat.com','apple.com','w3.org','xweb','json.org','wx.qq.com','msdk','bugly',
         'qcloud.com','github.com','schema.org','googleapis','whatwg','ecma','w3c']

urls = set()
for m in re.finditer(rb"https?://[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9][-a-zA-Z0-9./_?=&%#:@+]*", all_data):
    url = m.group().decode("ascii", errors="replace")
    if len(url) > 20:
        clean = url.rstrip(".,;)\"'<>\\")
        urls.add(clean)

print(f"\n=== Non-WeChat URLs ({len(urls)}) ===")
found = [u for u in sorted(urls) if not any(n in u.lower() for n in noise)]
for u in found:
    print(f"  {u}")
if not found:
    print("  (none found - all are WeChat noise)")

# Also search for domain-like strings
domains = set()
for m in re.finditer(rb"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?", all_data):
    d = m.group().decode("ascii", errors="replace").lower()
    if len(d) > 6 and "." in d and not d[0].isdigit():
        domains.add(d)

print(f"\n=== Non-WeChat domains ({len(domains)}) ===")
found_d = [d for d in sorted(domains) if not any(n in d for n in noise)]
for d in found_d:
    print(f"  {d}")
if not found_d:
    print("  (none found - all are WeChat noise)")
