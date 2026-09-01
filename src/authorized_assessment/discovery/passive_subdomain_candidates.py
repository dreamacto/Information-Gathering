"""subfinder + dnsx 被动/已知候选模式（实施规格 7.2；Batch 16）。

限制（规格 7.2 原文）：被动源或本地缓存导入；不默认进行公网主动枚举；CT 结果
人工/缓存导入；新发现域名先 confirmation_required，不能直接纳入扫描。

三个纯离线能力，模块自身永不执行工具、永不发 DNS/HTTP 请求：

  plan_subfinder  被动子域发现计划：单根域、最小旗标（-d/-o）；主动枚举旗标
                  -active 在 FORBIDDEN 列表，计划路径上不存在（subfinder 默认
                  被动，主动需要显式 -active——本模块从源头排除）。
  plan_dnsx       已知候选 DNS 解析计划：-l 清单模式；字典爆破旗标 -w 在
                  FORBIDDEN 列表，计划路径上不存在。
  ingest          操作者导入的被动源/CT 缓存结果行（host+source）对照授权
                  scope 根域做确定性后缀匹配（host == 根域 或 host 以
                  "." + 根域 结尾）：命中 → in_scope；未命中 →
                  confirmation_required（ROE：新资产所有权确认与目标登记前置，
                  绝不直接纳入扫描）。scope 缺失 fail-closed：全部
                  confirmation_required。
  filter_known_candidates  只有 in_scope 处置的 host 才能进入 dnsx 已知候选
                  解析清单；confirmation_required / duplicate 被排除。

工具状态来自 tools/tool_registry.json（subfinder / dnsx 两个 tool_id）：未登记、
非 active 或路径不可解析 → executable=false fail-closed（规格 7.1：不得伪装可
执行）。处置行为发现门控（非 finding 候选行），不复用 8 状态枚举。
"""
from __future__ import annotations

import re
from pathlib import Path

from authorized_assessment.tools import registry as tool_registry

SUBFINDER_TOOL_ID = "subfinder"
DNSX_TOOL_ID = "dnsx"

# 计划禁入旗标：主动枚举 / 字典爆破（规格 7.2 红线的计划路径级实现）。
SUBFINDER_FORBIDDEN_FLAGS: tuple[str, ...] = ("-active", "-nf", "-nuts")
DNSX_FORBIDDEN_FLAGS: tuple[str, ...] = ("-w",)

DISPOSITION_VALUES: tuple[str, ...] = ("in_scope", "confirmation_required", "duplicate")

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_FORBIDDEN_DOMAIN_CHARS = set(" \t\r\n/:?#@&=+$,%!~^*()'\"`|<>[]{}")


def _validate_domain(domain: str, label: str) -> list[str]:
    violations: list[str] = []
    value = (domain or "").strip().rstrip(".").lower()
    if not value:
        violations.append(f"{label}: 域名为空")
        return violations
    if any(ch in _FORBIDDEN_DOMAIN_CHARS for ch in value):
        violations.append(f"{label}: 域名含非法字符或空白（注入面拒绝）")
    elif not _DOMAIN_RE.match(value):
        violations.append(f"{label}: 不是合法域名形态: {domain!r}")
    return violations


def _resolve_tool(tool_id: str, registry_path: str | Path | None, root: Path) -> dict:
    if registry_path is None:
        registry_path = root / "tools" / "tool_registry.json"
    result = {
        "tool_id": tool_id,
        "registered": False,
        "status": "unregistered",
        "path": "",
        "version": "",
        "path_resolved": False,
        "executable": False,
        "reason": f"{tool_id} 未登记于 tools/tool_registry.json（规格 7.1：不得伪装可执行）",
    }
    data, err = tool_registry.load_registry(registry_path)
    if err or not isinstance(data, dict):
        result["status"] = "registry_unreadable"
        result["reason"] = f"tool registry 不可读：{err or '结构缺失'}"
        return result
    for entry in data.get("tools", []):
        if not isinstance(entry, dict) or str(entry.get("tool_id")) != tool_id:
            continue
        status = str(entry.get("status") or "")
        path = str(entry.get("path") or "")
        resolved = tool_registry.resolve_tool_path(path, root) if path else None
        exists = bool(resolved is not None and str(path).strip() and resolved.exists())
        result.update(
            registered=True, status=status, path=path,
            version=str(entry.get("version") or ""), path_resolved=exists,
        )
        if status != "active":
            result["reason"] = f"{tool_id} registry 状态为 {status!r}，不可执行"
        elif not exists:
            result["reason"] = f"{tool_id} 登记路径不可解析：{path!r}"
        else:
            result["reason"] = f"{tool_id} 已登记且路径可解析（计划可交操作者执行；本模块不代执行）"
            result["executable"] = True
        return result
    return result


def plan_subfinder(
    domain: str,
    *,
    output_path: str | Path,
    registry_path: str | Path | None = None,
    root: str | Path | None = None,
) -> tuple[dict, list[str]]:
    """subfinder 被动模式计划（单根域；-active 永不出现在计划中；零执行）。"""
    if root is None:
        root = Path(__file__).resolve().parents[3]
    root = Path(root)
    violations = _validate_domain(domain, "subfinder plan")
    tool = _resolve_tool(SUBFINDER_TOOL_ID, registry_path, root)
    value = (domain or "").strip().rstrip(".").lower()
    args = [
        tool["path"] or "subfinder",
        "-d",
        value,
        "-o",
        str(output_path),
    ]
    plan = {
        "plan_only": True,
        "tool_id": SUBFINDER_TOOL_ID,
        "tool_status": tool["status"],
        "tool_path": tool["path"],
        "executable": bool(tool["executable"] and not violations),
        "single_domain": True,
        "domain": value,
        "passive_only": True,
        "args": args,
        "command": " ".join(str(a) for a in args),
        "forbidden_flags": list(SUBFINDER_FORBIDDEN_FLAGS),
        "note": "被动源查询；新发现域名必须经 ingest scope 门控，confirmation_required 不进扫描",
        "reason": tool["reason"],
    }
    return plan, violations


def plan_dnsx(
    candidates_file: str | Path,
    *,
    output_path: str | Path,
    registry_path: str | Path | None = None,
    root: str | Path | None = None,
) -> tuple[dict, list[str]]:
    """dnsx 已知候选解析计划（-l 清单模式；-w 字典爆破永不出现；零执行）。

    candidates_file 必须只含 filter_known_candidates 放行的 in_scope host
    （调用方责任；本模块校验文件存在与行形态，逐行归属校验在 filter 层）。
    """
    if root is None:
        root = Path(__file__).resolve().parents[3]
    root = Path(root)
    violations: list[str] = []
    tool = _resolve_tool(DNSX_TOOL_ID, registry_path, root)
    file_path = Path(candidates_file)
    lines: list[str] = []
    if not file_path.is_file():
        violations.append(f"dnsx plan: 已知候选清单不存在：{file_path}")
    else:
        for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
            host = line.strip().rstrip(".").lower()
            if not host:
                continue
            violations.extend(_validate_domain(host, f"dnsx plan 行 {host!r}"))
            lines.append(host)
    args = [
        tool["path"] or "dnsx",
        "-l",
        str(file_path),
        "-o",
        str(output_path),
        "-silent",
    ]
    plan = {
        "plan_only": True,
        "tool_id": DNSX_TOOL_ID,
        "tool_status": tool["status"],
        "tool_path": tool["path"],
        "executable": bool(tool["executable"] and not violations),
        "mode": "known_candidate_resolution",
        "candidates_file": str(file_path),
        "candidate_count": len(lines),
        "args": args,
        "command": " ".join(str(a) for a in args),
        "forbidden_flags": list(DNSX_FORBIDDEN_FLAGS),
        "note": "只解析已知候选；解析结果不等于活性/授权，后续仍走活性阶段与 scope 复核",
        "reason": tool["reason"],
    }
    return plan, violations


def scope_match(host: str, scope_roots: list[str]) -> bool:
    """确定性 scope 匹配：host 等于某授权根域，或以其为后缀（"." + 根域 结尾）。"""
    host = (host or "").strip().rstrip(".").lower()
    for entry in scope_roots or []:
        root_domain = str(entry or "").strip().rstrip(".").lower()
        if not root_domain:
            continue
        if host == root_domain or host.endswith("." + root_domain):
            return True
    return False


def ingest_passive_results(
    results: list[dict],
    scope_roots: list[str] | None,
    *,
    label: str = "passive_ingest",
) -> tuple[list[dict], dict, list[str]]:
    """被动源/CT 缓存结果 → (处置行, 汇总, 违例)。

    结果行契约：{"host": str, "source": str}（source ∈ 被动源名/"ct_cache_import"）。
    scope_roots 缺失/为空 → fail-closed：全部 confirmation_required。
    """
    rows: list[dict] = []
    violations: list[str] = []
    seen: dict[str, int] = {}
    scope_provided = bool(scope_roots)
    for index, raw in enumerate(results, start=1):
        row_label = f"{label}[{index}]"
        if not isinstance(raw, dict):
            violations.append(f"{row_label}: 结果必须是键值映射")
            continue
        host = str(raw.get("host") or "").strip().rstrip(".").lower()
        source = str(raw.get("source") or "").strip()
        if not host:
            violations.append(f"{row_label}: 缺少 host")
            continue
        violations.extend(_validate_domain(host, row_label))
        if host in seen:
            rows.append(
                {
                    "candidate_id": f"passive-{index:04d}",
                    "disposition": "duplicate",
                    "host": host,
                    "source": source,
                    "reason": f"与第 {seen[host]} 条结果重复（同 host）",
                }
            )
            continue
        seen[host] = index
        in_scope = scope_provided and scope_match(host, scope_roots)
        disposition = "in_scope" if in_scope else "confirmation_required"
        if in_scope:
            reason = "host 落在授权 scope 根域内（后缀匹配）"
        elif not scope_provided:
            reason = "scope 未提供 fail-closed：新资产必须先做所有权确认（ROE）"
        else:
            reason = "新发现域名：所有权确认与目标登记前不纳入任何扫描（ROE/规格 7.2）"
        rows.append(
            {
                "candidate_id": f"passive-{index:04d}",
                "disposition": disposition,
                "host": host,
                "source": source,
                "reason": reason,
            }
        )
    counts = {d: 0 for d in DISPOSITION_VALUES}
    for r in rows:
        counts[r["disposition"]] += 1
    summary = {
        "category": "passive_subdomain",
        "scope_provided": scope_provided,
        "disposition_counts": counts,
        "total": len(rows),
        "reason": (
            f"被动子域处置：in_scope={counts['in_scope']}，"
            f"confirmation_required={counts['confirmation_required']}（新资产确认前置）"
        ),
    }
    return rows, summary, violations


def filter_known_candidates(
    dispositions: list[dict], *, label: str = "known_candidates"
) -> tuple[list[str], list[str]]:
    """从处置行提取可进入 dnsx 解析清单的 host 列表。

    只有 disposition == in_scope 的 host 放行；confirmation_required / duplicate
    一律排除（返回违例说明被排除数，便于审计"新资产未直接纳入"）。
    """
    allowed: list[str] = []
    excluded = 0
    for row in dispositions:
        if not isinstance(row, dict):
            excluded += 1
            continue
        if row.get("disposition") == "in_scope":
            allowed.append(str(row.get("host") or ""))
        else:
            excluded += 1
    if excluded:
        return sorted(set(allowed)), [f"{label}: {excluded} 行非 in_scope 处置被排除（新资产确认前置）"]
    return sorted(set(allowed)), []
