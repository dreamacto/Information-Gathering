import argparse
import csv
import re
from pathlib import Path


DEFAULT_PATTERNS = [
    "api/app/nrii",
    "api/app/nrii/authority",
    "instrument/export",
    "authority/upload",
    "deleteInstru",
    "auditdelete",
    "uploadImgServer",
    "uploadVideoServer",
    "customUploadImg",
    "FileHost",
    "Authorization",
    "authorization",
    "access_token",
    "invalid_grant",
    "localStorage",
    "sessionStorage",
    "/User/Login",
    "/login/smscode",
    "getCaptcha",
    "ChangePwd",
    "Register",
    "Management/details",
]


def read_text(path: Path) -> str:
    data = path.read_bytes()
    for enc in ("utf-8", "utf-8-sig", "gb18030", "gbk"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def compact(s: str) -> str:
    s = s.replace("\\/", "/")
    s = re.sub(r"\s+", " ", s)
    return s


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("js_file")
    parser.add_argument("--out", default="runs/js_static_analysis_20260709/context_hits.csv")
    parser.add_argument("--window", type=int, default=700)
    parser.add_argument("--max-per-pattern", type=int, default=80)
    parser.add_argument("--pattern", action="append")
    args = parser.parse_args()

    text = read_text(Path(args.js_file))
    patterns = args.pattern or DEFAULT_PATTERNS
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for pat in patterns:
        count = 0
        for m in re.finditer(re.escape(pat), text, re.I):
            start = max(0, m.start() - args.window)
            end = min(len(text), m.end() + args.window)
            rows.append({
                "pattern": pat,
                "position": m.start(),
                "context": compact(text[start:end]),
            })
            count += 1
            if count >= args.max_per_pattern:
                break

    with out.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["pattern", "position", "context"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} context rows to {out}")


if __name__ == "__main__":
    main()
