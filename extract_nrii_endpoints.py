import argparse
import csv
import re
from pathlib import Path


BASE_RE = re.compile(r'new\s+\w+\("(?P<base>api/app/nrii[^"]*)"\)')
METHOD_SUFFIX_RE = re.compile(
    r'e(?:\.\["(?P<name1>[^"]+)"\]|\.(?P<name2>[A-Za-z_$][\w$]*))\s*=\s*function\([^)]*\)\{return\s+e\.(?P<verb>get|post|delete|put)\(""\.concat\(e\.url,"(?P<suffix>[^"]*)"\)',
    re.I,
)
DIRECT_API_RE = re.compile(
    r'e(?:\.\["(?P<name1>[^"]+)"\]|\.(?P<name2>[A-Za-z_$][\w$]*))\s*=\s*function\([^)]*\)\{return\s+e\.(?P<verb>get|post|delete|put)\("(?P<endpoint>api/app/nrii[^"]*)"',
    re.I,
)
FULL_API_STRING_RE = re.compile(r'"(?P<endpoint>api/app/nrii/[A-Za-z0-9_./-]{2,})"')


RISK_WORDS = [
    ("upload", 5, "upload"),
    ("delete", 5, "delete"),
    ("disable", 4, "disable"),
    ("audit", 4, "audit"),
    ("post", 3, "write"),
    ("save", 3, "write"),
    ("apply", 3, "apply"),
    ("export", 4, "export"),
    ("report", 3, "report"),
    ("details", 2, "details"),
    ("anonymous", 4, "anonymous-flow"),
    ("sms", 4, "sms"),
    ("verify", 4, "verify"),
    ("login", 5, "auth"),
    ("token", 5, "auth"),
    ("user", 3, "user"),
    ("management", 3, "management"),
    ("regulation", 2, "content-admin"),
    ("instrument", 2, "instrument"),
    ("order", 2, "order"),
]


def read_text(path: Path) -> str:
    data = path.read_bytes()
    for enc in ("utf-8", "utf-8-sig", "gb18030", "gbk"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def score_endpoint(endpoint: str, verb: str) -> tuple[int, str]:
    low = endpoint.lower()
    score = 0
    reasons = []
    if verb.lower() in {"post", "put", "delete"}:
        score += 4
        reasons.append(f"method:{verb.lower()}")
    for word, points, reason in RISK_WORDS:
        if word in low:
            score += points
            reasons.append(reason)
    return score, "|".join(sorted(set(reasons)))


def add(rows, seen, endpoint, verb="", name="", base="", source=""):
    endpoint = endpoint.replace("\\/", "/")
    key = (endpoint, verb.lower(), name, base)
    if key in seen:
        return
    seen.add(key)
    score, reasons = score_endpoint(endpoint, verb)
    rows.append({
        "score": score,
        "verb": verb.upper(),
        "name": name,
        "endpoint": endpoint,
        "base": base,
        "reasons": reasons,
        "source": source,
    })


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("js_file")
    parser.add_argument("--out", default="runs/js_static_analysis_20260709/nrii_endpoints.csv")
    parser.add_argument("--window", type=int, default=12000)
    args = parser.parse_args()

    text = read_text(Path(args.js_file))
    rows = []
    seen = set()

    for m in BASE_RE.finditer(text):
        base = m.group("base")
        start = max(0, m.start() - args.window)
        chunk = text[start:m.start()]
        for mm in METHOD_SUFFIX_RE.finditer(chunk):
            name = mm.group("name1") or mm.group("name2") or ""
            suffix = mm.group("suffix")
            add(rows, seen, base + suffix, mm.group("verb"), name, base, "base+suffix")

    for mm in DIRECT_API_RE.finditer(text):
        name = mm.group("name1") or mm.group("name2") or ""
        add(rows, seen, mm.group("endpoint"), mm.group("verb"), name, "", "direct-call")

    for mm in FULL_API_STRING_RE.finditer(text):
        add(rows, seen, mm.group("endpoint"), "", "", "", "string")

    rows.sort(key=lambda r: (-int(r["score"]), r["endpoint"], r["verb"]))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["score", "verb", "name", "endpoint", "base", "reasons", "source"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} endpoints to {out}")
    for row in rows[:40]:
        print(f'{row["score"]:>2} {row["verb"]:<6} {row["endpoint"]} [{row["reasons"]}]')


if __name__ == "__main__":
    main()
