#!/usr/bin/env python3
"""W5 验证器：证明 wz/xcx/fh 三 skill 的硬约束改造已落地且一致。

跨会话可复现：未来任何会话只需运行
    python scripts/verify_w5.py
即可自证 W5 是否成功，无需依赖对话记忆。

判定项：
  1) 四目录(.claude/.opencode/.agents/skill-deliverables) × 三 skill 的 SKILL.md
     均含 W5 硬约束块(Highest-priority hard constraints)+阶段门。
  2) fh 四地 SKILL.md 哈希一致(单一真源=skill-deliverables/fh)。
  3) skill-deliverables 下的 wz/xcx/fh.zip 内 SKILL.md 含 W5 块。
"""
import os
import sys
import hashlib
import zipfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS = ["wz", "xcx", "fh"]
DIRS = [".claude/skills", ".opencode/skills", ".agents/skills", "skill-deliverables"]
BLOCK = "Highest-priority hard constraints"
ok = True


def has_gate(t):
    return ("stage gate" in t) or ("one batch" in t) or ("one stage" in t)


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


print("=== 检查1: 四目录×三skill 均含 W5 硬约束块+阶段门 ===")
for d in DIRS:
    for s in SKILLS:
        p = os.path.join(BASE, d, s, "SKILL.md")
        if not os.path.exists(p):
            print(f"  FAIL 缺失 {d}/{s}")
            ok = False
            continue
        t = read(p)
        good = BLOCK in t and has_gate(t)
        if not good:
            ok = False
        print(f"  {'OK ' if good else 'FAIL'} {d:20}/{s}")

print("\n=== 检查2: fh 四地为单一真源(哈希一致) ===")
hs = {}
for d in DIRS:
    p = os.path.join(BASE, d, "fh", "SKILL.md")
    hs[d] = hashlib.md5(read(p).encode()).hexdigest()[:10]
for d, v in hs.items():
    print(f"  {d:20} {v}")
if len(set(hs.values())) != 1:
    print("  FAIL fh 四地不一致")
    ok = False
else:
    print("  OK fh 四地哈希一致（真源=skill-deliverables/fh）")

print("\n=== 检查3: wz/xcx/fh.zip 内含 SKILL.md 含 W5 块 ===")
for s in SKILLS:
    zp = os.path.join(BASE, "skill-deliverables", s + ".zip")
    if not os.path.exists(zp):
        print(f"  FAIL 缺失 {s}.zip")
        ok = False
        continue
    z = zipfile.ZipFile(zp)
    sk = [x for x in z.namelist() if x.endswith("SKILL.md")][0]
    good = BLOCK in z.read(sk).decode("utf-8", "replace")
    if not good:
        ok = False
    print(f"  {'OK ' if good else 'FAIL'} {s}.zip 内SKILL.md含W5块")

print("\n=== 总判定 ===")
print("W5 施工成功 ✅" if ok else "W5 存在问题 ❌")
sys.exit(0 if ok else 1)
