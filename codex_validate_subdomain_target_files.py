import json
import os
import sys
from collections import Counter
from pathlib import Path


os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


WORKSPACE = Path(r"D:\PythonSource\PythonProjects\PythonProject4")
RUN_DIR = WORKSPACE / "runs" / "20260728_115448_one_click_full_weak"
sys.path.insert(0, str(WORKSPACE))

from exercise_runtime import load_targets  # noqa: E402


def summarize(path: Path) -> dict:
    targets = load_targets(path)
    schemes = Counter(target.scheme for target in targets)
    hosts = [target.host for target in targets]
    return {
        "path": str(path),
        "loaded_targets": len(targets),
        "unique_hosts": len(set(hosts)),
        "schemes": dict(schemes),
        "empty_hosts": sum(not host for host in hosts),
        "first_three_urls": [target.url for target in targets[:3]],
        "first_three_names": [target.name for target in targets[:3]],
    }


def main() -> int:
    output = [
        summarize(RUN_DIR / "subdomains_dedup.txt"),
        summarize(RUN_DIR / "subdomains_for_next_run.txt"),
    ]
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if all(item["loaded_targets"] == 669 for item in output) else 1


if __name__ == "__main__":
    raise SystemExit(main())
