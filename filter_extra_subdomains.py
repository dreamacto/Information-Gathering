import argparse
import csv
import ipaddress
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse


ALLOWED_GOV_SUFFIXES = (
    ".gxzf.gov.cn",
    ".nanning.gov.cn",
    ".liuzhou.gov.cn",
    ".hechi.gov.cn",
    ".wuzhou.gov.cn",
    ".baise.gov.cn",
    ".guilin.gov.cn",
    ".qinzhou.gov.cn",
    ".beihai.gov.cn",
    ".fangchenggang.gov.cn",
    ".guigang.gov.cn",
    ".yulin.gov.cn",
    ".hezhou.gov.cn",
    ".laibin.gov.cn",
    ".chongzuo.gov.cn",
)

NOISY_PREFIXES = (
    "anhui.",
    "beijing.",
    "bj.",
    "chongqing.",
    "cq.",
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
    "neimenggu.",
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


def normalize_host(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc or parsed.path
    value = value.split("|", 1)[0].strip()
    value = value.split("/", 1)[0].strip()
    value = value.rsplit("@", 1)[-1]
    if ":" in value and not value.startswith("["):
        value = value.split(":", 1)[0]
    return value.strip(".").lower()


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def read_hosts(path: Path) -> list[str]:
    hosts: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        host = normalize_host(line)
        if host and "." in host and not is_ip(host):
            hosts.append(host)
    return sorted(set(hosts))


def parent_match(host: str, seeds: list[str]) -> str:
    matches = [seed for seed in seeds if host == seed or host.endswith("." + seed)]
    if not matches:
        return ""
    return max(matches, key=len)


def is_allowed_gov_host(host: str) -> bool:
    if host in {"gxzf.gov.cn", "nanning.gov.cn", "liuzhou.gov.cn", "hechi.gov.cn"}:
        return True
    return any(host.endswith(suffix) for suffix in ALLOWED_GOV_SUFFIXES)


def is_noisy_cross_region(host: str) -> bool:
    return any(host.startswith(prefix) for prefix in NOISY_PREFIXES)


def collect_oneforall_hosts(out_dir: Path) -> dict[str, set[str]]:
    by_host: dict[str, set[str]] = defaultdict(set)
    for csv_path in out_dir.rglob("*.csv"):
        with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                host = normalize_host(row.get("subdomain") or row.get("url") or "")
                if host and "." in host and not is_ip(host):
                    by_host[host].add(row.get("source") or csv_path.stem)
    return by_host


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oneforall-dir", type=Path, required=True)
    parser.add_argument("--seed-domains", type=Path, required=True)
    parser.add_argument("--original-targets", type=Path, required=True)
    parser.add_argument("--out-prefix", type=Path, required=True)
    args = parser.parse_args()

    seeds = read_hosts(args.seed_domains)
    originals = set(read_hosts(args.original_targets))
    by_host = collect_oneforall_hosts(args.oneforall_dir)

    scan_ready: list[str] = []
    pending: list[str] = []
    rejected: list[dict[str, str]] = []

    for host in sorted(by_host):
        if host in originals:
            rejected.append({"host": host, "reason": "already_in_original_targets"})
            continue
        parent = parent_match(host, seeds)
        if parent:
            if is_noisy_cross_region(host):
                pending.append(host)
            else:
                scan_ready.append(host)
            continue
        if is_allowed_gov_host(host) and not is_noisy_cross_region(host):
            pending.append(host)
            continue
        rejected.append({"host": host, "reason": "outside_seed_scope_or_cross_region"})

    scan_ready = sorted(set(scan_ready))
    pending = sorted(set(pending) - set(scan_ready))

    ready_path = args.out_prefix.with_name(args.out_prefix.name + "_scan_ready.txt")
    pending_path = args.out_prefix.with_name(args.out_prefix.name + "_pending_apply.txt")
    rejected_path = args.out_prefix.with_name(args.out_prefix.name + "_rejected.csv")
    summary_path = args.out_prefix.with_name(args.out_prefix.name + "_summary.md")

    write_lines(ready_path, scan_ready)
    write_lines(pending_path, pending)

    with rejected_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["host", "reason"])
        writer.writeheader()
        writer.writerows(rejected)

    suffix_counts = Counter()
    for host in scan_ready:
        parent = parent_match(host, seeds) or "(allowed-gov-pending)"
        suffix_counts[parent] += 1

    lines = [
        "# Extra Subdomain Scope Filter Summary",
        "",
        f"- OneForAll hosts: {len(by_host)}",
        f"- Seed domains: {len(seeds)}",
        f"- Original target hosts: {len(originals)}",
        f"- Scan-ready subdomains: {len(scan_ready)}",
        f"- Pending/apply-review subdomains: {len(pending)}",
        f"- Rejected/noisy subdomains: {len(rejected)}",
        "",
        "## Top Scan-Ready Parents",
        "",
    ]
    for parent, count in suffix_counts.most_common(30):
        lines.append(f"- {parent}: {count}")
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(summary_path)
    print(ready_path)
    print(pending_path)
    print(rejected_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
