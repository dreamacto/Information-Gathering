"""离线 SBOM/依赖审计（实施规格 7.2 离线 SBOM/依赖审计；Batch 16）。

接入（规格 7.2）：preflight / infrastructure_testing / reporting。

规格红线："优先输出 lockfile、版本、依赖关系和本地 advisory cache 结果。无
advisory 数据库时只能报告'依赖清单'和'需要人工复核'，不能伪造漏洞结论。"

纯离线、零网络、零执行：
  - build_sbom_from_directory：扫描给定目录的 requirements*.txt /
    package-lock.json / package.json，输出确定性依赖清单行
    （ecosystem/name/version/source_file/pinned/direct/relations_available）；
    解析失败的行记违例，不猜测。
  - advisory 匹配：可选本地 advisory cache（操作者手工维护的 JSON：
    {"packages": {"<name>": [{"cve","affected","summary"}...]}}），affected 为
    ==/!=/</<=/>/>= 点分版本约束（可空格）；命中 → advisory_hit_manual_review
    （仅人工复核线索，非漏洞结论）；无数据 → no_advisory_data；约束不可解析 →
    advisory_unparsed fail-closed。
  - 顶层纪律：本模块输出不存在 vulnerable/confirmed 概念——
    validate_sbom_row 拒绝此类状态（不伪造漏洞结论）。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

SBOM_CATEGORY = "sbom_inventory"

# 依赖清单行合法状态（无漏洞语义；validator 拒绝 vulnerable/confirmed 等）。
SBOM_ROW_STATUSES: tuple[str, ...] = ("inventory", "duplicate")

ADVISORY_STATUSES: tuple[str, ...] = (
    "no_advisory_data",
    "advisory_hit_manual_review",
    "advisory_unparsed",
)

_REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*([<>=!~]=?)\s*([A-Za-z0-9][A-Za-z0-9._+-]*)")

# 常见非依赖行前缀（pip 选项/include）——记违例不猜测。
_SKIP_LINE_PREFIXES = ("-", "--")


def _parse_version(version: str) -> tuple[int, ...] | None:
    """点分版本 → 数值元组（纯数字段）；含非数字段返回 None（fail-closed）。"""
    parts = str(version or "").strip().split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def _satisfies(version: str, constraint: str) -> bool | None:
    """版本是否满足约束（==/!=/</<=/>/>=）；不可解析返回 None（fail-closed）。"""
    text = (constraint or "").strip()
    match = re.match(r"^(==|!=|<=|>=|<|>)\s*(.+)$", text)
    if not match:
        return None
    op, target = match.group(1), match.group(2).strip()
    left, right = _parse_version(version), _parse_version(target)
    if left is None or right is None:
        return None
    # 补齐长度后逐段比较（2.28 == 2.28.0）。
    width = max(len(left), len(right))
    left = left + (0,) * (width - len(left))
    right = right + (0,) * (width - len(right))
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    if op == ">":
        return left > right
    return left >= right


def parse_advisory_cache(path: str | Path) -> dict:
    """读取本地 advisory cache（操作者手工维护）；缺失/损坏返回空表并留痕键。"""
    file_path = Path(path)
    if not file_path.is_file():
        return {"packages": {}, "cache_available": False, "cache_path": str(file_path)}
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"packages": {}, "cache_available": False, "cache_path": str(file_path), "error": "unparseable"}
    packages = data.get("packages") if isinstance(data.get("packages"), dict) else {}
    return {"packages": packages, "cache_available": True, "cache_path": str(file_path)}


def _match_advisories(name: str, version: str, cache: dict | None) -> tuple[str, list[dict]]:
    """advisory 匹配 → (advisory_status, 命中条目列表)。"""
    if not cache or not cache.get("cache_available"):
        return "no_advisory_data", []
    entries = cache.get("packages", {}).get(name) or []
    if not entries:
        return "no_advisory_data", []
    hits: list[dict] = []
    unparsed = False
    for entry in entries:
        if not isinstance(entry, dict):
            unparsed = True
            continue
        result = _satisfies(version, str(entry.get("affected") or ""))
        if result is None:
            unparsed = True
            continue
        if result:
            hits.append(
                {
                    "cve": str(entry.get("cve") or ""),
                    "affected": str(entry.get("affected") or ""),
                    "summary": str(entry.get("summary") or ""),
                }
            )
    if hits:
        return "advisory_hit_manual_review", hits
    if unparsed:
        return "advisory_unparsed", []
    return "no_advisory_data", []


def _row(ecosystem: str, name: str, version: str, source_file: str, *, pinned: bool,
         direct: bool, relations_available: bool, index: int, advisory_status: str,
         advisories: list[dict], reason: str = "") -> dict:
    return {
        "component_id": f"sbom-{index:04d}",
        "status": "inventory",
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "source_file": source_file,
        "version_pinned": pinned,
        "direct": direct,
        "relations_available": relations_available,
        "advisory_status": advisory_status,
        "advisories": advisories,
        "reason": reason or "依赖清单行（非漏洞结论；advisory 命中仅为人工复核线索）",
    }


def _parse_requirements_text(text: str, source: str, cache: dict | None, start_index: int) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    violations: list[str] = []
    index = start_index
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(_SKIP_LINE_PREFIXES):
            violations.append(f"{source}:{lineno}: pip 选项/依赖组行不支持离线展开，已跳过: {line!r}")
            continue
        match = _REQUIREMENT_RE.match(line)
        if not match:
            violations.append(f"{source}:{lineno}: 无法解析的依赖行（不猜测）: {line!r}")
            continue
        name, op, version = match.groups()
        pinned = op == "=="
        advisory_status, advisories = _match_advisories(name, version, cache)
        index += 1
        rows.append(
            _row(
                "python", name, version, f"{source}:{lineno}",
                pinned=pinned, direct=True, relations_available=False,
                index=index, advisory_status=advisory_status, advisories=advisories,
                reason=(
                    "requirements 扁平清单：直接依赖；传递关系不可用（relations_available=false）"
                ),
            )
        )
    return rows, violations


def _parse_package_lock(data: dict, source: str, cache: dict | None) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    violations: list[str] = []
    packages = data.get("packages")
    index = 0
    if isinstance(packages, dict):
        root_deps = packages.get("", {}).get("dependencies", {}) if isinstance(packages.get(""), dict) else {}
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict):
                continue
            name = key.removeprefix("node_modules/")
            version = str(entry.get("version") or "")
            if not name or not version:
                violations.append(f"{source}: packages[{key!r}] 缺少 name/version（不猜测）")
                continue
            direct = name in root_deps
            advisory_status, advisories = _match_advisories(name, version, cache)
            index += 1
            rows.append(
                _row(
                    "npm", name, version, source,
                    pinned=True, direct=direct, relations_available=True,
                    index=index, advisory_status=advisory_status, advisories=advisories,
                    reason="package-lock v2/v3：关系可从 packages[].dependencies 恢复",
                )
            )
        return rows, violations
    # v1 形态：dependencies 递归。
    def walk(deps: dict) -> None:
        nonlocal index
        if not isinstance(deps, dict):
            return
        for name, entry in deps.items():
            version = str((entry or {}).get("version") or "") if isinstance(entry, dict) else ""
            if not version:
                violations.append(f"{source}: dependencies[{name!r}] 缺少 version（不猜测）")
                continue
            advisory_status, advisories = _match_advisories(name, version, cache)
            index += 1
            rows.append(
                _row(
                    "npm", name, version, source,
                    pinned=True, direct=False, relations_available=True,
                    index=index, advisory_status=advisory_status, advisories=advisories,
                    reason="package-lock v1：dependencies 递归（direct 标记不可用）",
                )
            )
            walk((entry or {}).get("dependencies") or {})

    if isinstance(data.get("dependencies"), dict):
        walk(data["dependencies"])
    else:
        violations.append(f"{source}: package-lock 结构不可识别（v1 dependencies / v2+ packages 均缺失）")
    return rows, violations


def _parse_package_json(data: dict, source: str, cache: dict | None) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    violations: list[str] = []
    index = 0
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, constraint in deps.items():
            version = str(constraint or "").strip()
            pinned = version.startswith("=") or (version[:1].isdigit())
            advisory_status, advisories = _match_advisories(name, version.lstrip("^~="), cache)
            index += 1
            rows.append(
                _row(
                    "npm", name, version, f"{source}#{section}",
                    pinned=pinned, direct=True, relations_available=False,
                    index=index, advisory_status=advisory_status, advisories=advisories,
                    reason="package.json 无锁定：版本可能为范围表达式，advisory 比较按数字段尽力解析",
                )
            )
    return rows, violations


def build_sbom_from_directory(
    source_root: str | Path,
    advisory_cache: dict | None = None,
    *,
    label: str = "sbom",
) -> tuple[list[dict], dict, list[str]]:
    """离线构建依赖清单 → (清单行, 汇总, 违例)。零网络、零执行、幂等。"""
    root = Path(source_root)
    rows: list[dict] = []
    violations: list[str] = []
    if not root.is_dir():
        return rows, {}, [f"{label}: 目录不存在：{root}"]

    seen: set[tuple[str, str, str]] = set()
    for req_path in sorted(root.glob("requirements*.txt")):
        text = req_path.read_text(encoding="utf-8", errors="replace")
        parsed, parsed_violations = _parse_requirements_text(text, req_path.name, advisory_cache, len(rows))
        rows.extend(parsed)
        violations.extend(parsed_violations)
    for lock_path in sorted(root.glob("package-lock.json")):
        try:
            data = json.loads(lock_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            violations.append(f"{lock_path.name}: JSON 解析失败（不猜测）: {exc}")
            continue
        parsed, parsed_violations = _parse_package_lock(data, lock_path.name, advisory_cache)
        rows.extend(parsed)
        violations.extend(parsed_violations)
    for pkg_path in sorted(root.glob("package.json")):
        try:
            data = json.loads(pkg_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            violations.append(f"{pkg_path.name}: JSON 解析失败（不猜测）: {exc}")
            continue
        parsed, parsed_violations = _parse_package_json(data, pkg_path.name, advisory_cache)
        rows.extend(parsed)
        violations.extend(parsed_violations)

    deduped: list[dict] = []
    for row in rows:
        key = (row["ecosystem"], row["name"], row["version"], row["source_file"])
        if key in seen:
            row["status"] = "duplicate"
        else:
            seen.add(key)
        deduped.append(row)
        violations += validate_sbom_row(row, label=f"{label}[{row['component_id']}]")

    ecosystem_counts: dict[str, int] = {}
    advisory_counts = {s: 0 for s in ADVISORY_STATUSES}
    for row in deduped:
        if row["status"] == "inventory":
            ecosystem_counts[row["ecosystem"]] = ecosystem_counts.get(row["ecosystem"], 0) + 1
        advisory_counts[row["advisory_status"]] += 1
    cache_available = bool(advisory_cache and advisory_cache.get("cache_available"))
    summary = {
        "category": SBOM_CATEGORY,
        "source_root": str(root),
        "total_dependencies": len(deduped),
        "ecosystem_counts": ecosystem_counts,
        "advisory_status_counts": advisory_counts,
        "advisory_cache_available": cache_available,
        "conclusion": (
            "依赖清单与人工复核线索；本模块不输出漏洞结论"
            if cache_available
            else "无 advisory 数据：仅依赖清单与人工复核，不伪造漏洞结论"
        ),
        "reason": (
            f"SBOM：共 {len(deduped)} 项依赖；advisory 命中 "
            f"{advisory_counts['advisory_hit_manual_review']} 项（仅人工复核线索）"
        ),
    }
    return deduped, summary, violations


def validate_sbom_row(row: dict, label: str = "sbom_row") -> list[str]:
    """SBOM 行校验：inventory/duplicate 状态 + advisory 枚举 + 漏洞结论禁入。"""
    violations: list[str] = []
    if not isinstance(row, dict):
        return [f"{label}: 行必须是键值映射"]
    for field in ("component_id", "status", "ecosystem", "name", "version", "source_file"):
        if field not in row:
            violations.append(f"{label}: 缺少必需字段 {field}")
    status = str(row.get("status") or "")
    if status and status not in SBOM_ROW_STATUSES:
        if status.lower() in ("vulnerable", "confirmed", "candidate"):
            violations.append(
                f"{label}: status={status} 被拒绝——SBOM 模块不伪造漏洞结论（规格 7.2）"
            )
        else:
            violations.append(f"{label}.status 非法: {status!r}（允许值 {list(SBOM_ROW_STATUSES)}）")
    advisory_status = str(row.get("advisory_status") or "")
    if advisory_status and advisory_status not in ADVISORY_STATUSES:
        violations.append(
            f"{label}.advisory_status 非法: {advisory_status!r}（允许值 {list(ADVISORY_STATUSES)}）"
        )
    return violations
