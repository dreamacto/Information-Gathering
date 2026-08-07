import argparse
import csv
from collections import Counter
from pathlib import Path


GUANGXI_CITY_SUFFIXES = (
    ".nanning.gov.cn",
    ".liuzhou.gov.cn",
    ".guilin.gov.cn",
    ".wuzhou.gov.cn",
    ".beihai.gov.cn",
    ".fangchenggang.gov.cn",
    ".qinzhou.gov.cn",
    ".guigang.gov.cn",
    ".yulin.gov.cn",
    ".baise.gov.cn",
    ".hezhou.gov.cn",
    ".hechi.gov.cn",
    ".laibin.gov.cn",
    ".chongzuo.gov.cn",
)

GUANGXI_GOV_SUFFIXES = (
    ".gxzf.gov.cn",
    ".gxrd.gov.cn",
    ".gxjjw.gov.cn",
    ".gxi.gov.cn",
)

NATIONAL_GX_PATTERNS = (
    "guangxi.chinatax.gov.cn",
    ".guangxi.chinatax.gov.cn",
    ".gx-n-tax.gov.cn",
)

THIRD_PARTY_HINTS = (
    "gx",
    "guangxi",
    "nanning",
    "liuzhou",
    "guilin",
    "hechi",
    "baise",
    "qinzhou",
    "beihai",
    "wuzhou",
    "guigang",
    "yulin",
    "laibin",
    "chongzuo",
    "fangchenggang",
)

NOISE_PREFIXES = (
    "anhui.",
    "beijing.",
    "chongqing.",
    "fujian.",
    "gansu.",
    "guangdong.",
    "guizhou.",
    "hainan.",
    "hebei.",
    "heilongjiang.",
    "henan.",
    "hubei.",
    "hunan.",
    "jiangsu.",
    "jiangxi.",
    "jilin.",
    "liaoning.",
    "ningxia.",
    "qinghai.",
    "shaanxi.",
    "shandong.",
    "shanghai.",
    "shanxi.",
    "sichuan.",
    "tianjin.",
    "xinjiang.",
    "xizang.",
    "yunnan.",
    "zhejiang.",
)


def classify(host: str) -> tuple[str, int, str]:
    host = host.strip().lower()
    if not host:
        return ("empty", 0, "empty")
    if host.startswith(NOISE_PREFIXES):
        return ("reject_cross_region", 0, "province-prefix outside Guangxi")
    if host.endswith(GUANGXI_GOV_SUFFIXES):
        return ("gx_gov_direct", 100, "Guangxi government suffix")
    if host.endswith(GUANGXI_CITY_SUFFIXES):
        return ("gx_city_gov", 95, "Guangxi city government suffix")
    if any(host == p or host.endswith(p) for p in NATIONAL_GX_PATTERNS):
        return ("national_system_gx_branch", 90, "national vertical system Guangxi branch")
    if host.endswith(".gov.cn"):
        labels = host.split(".")
        if any(label.startswith("gx") or label in {"guangxi"} for label in labels):
            return ("gov_cn_gx_hint", 75, "gov.cn with gx/guangxi hint")
        return ("gov_cn_needs_manual", 55, "gov.cn but Guangxi ownership unclear")
    if host.endswith((".org.cn", ".com.cn", ".cn", ".com", ".net")):
        if any(hint in host for hint in THIRD_PARTY_HINTS):
            return ("third_party_gx_hint", 60, "non-gov domain with Guangxi/local hint")
        return ("third_party_unclear", 35, "non-gov domain, unclear ownership")
    return ("unknown", 20, "unknown suffix")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pending", type=Path, required=True)
    parser.add_argument("--out-prefix", type=Path, required=True)
    args = parser.parse_args()

    hosts = sorted(
        {
            line.strip().lower()
            for line in args.pending.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip()
        }
    )
    rows = []
    for host in hosts:
        category, score, reason = classify(host)
        rows.append({"host": host, "category": category, "score": score, "reason": reason})

    rows.sort(key=lambda row: (-int(row["score"]), row["category"], row["host"]))
    csv_path = args.out_prefix.with_name(args.out_prefix.name + "_classified.csv")
    high_path = args.out_prefix.with_name(args.out_prefix.name + "_high_confidence.txt")
    medium_path = args.out_prefix.with_name(args.out_prefix.name + "_manual_review.txt")
    reject_path = args.out_prefix.with_name(args.out_prefix.name + "_likely_noise.txt")
    summary_path = args.out_prefix.with_name(args.out_prefix.name + "_summary.md")

    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["host", "category", "score", "reason"])
        writer.writeheader()
        writer.writerows(rows)

    high = [row["host"] for row in rows if int(row["score"]) >= 90]
    medium = [row["host"] for row in rows if 55 <= int(row["score"]) < 90]
    reject = [row["host"] for row in rows if int(row["score"]) < 55]
    high_path.write_text("\n".join(high) + ("\n" if high else ""), encoding="utf-8")
    medium_path.write_text("\n".join(medium) + ("\n" if medium else ""), encoding="utf-8")
    reject_path.write_text("\n".join(reject) + ("\n" if reject else ""), encoding="utf-8")

    counts = Counter(row["category"] for row in rows)
    lines = [
        "# Pending Subdomain Classification Summary",
        "",
        f"- Total pending: {len(rows)}",
        f"- High confidence Guangxi/government branch: {len(high)}",
        f"- Manual review: {len(medium)}",
        f"- Likely noise/low confidence: {len(reject)}",
        "",
        "## Category Counts",
        "",
    ]
    for category, count in counts.most_common():
        lines.append(f"- {category}: {count}")
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(summary_path)
    print(csv_path)
    print(high_path)
    print(medium_path)
    print(reject_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
