# -*- coding: utf-8 -*-
"""W6 · fh 复核子代理编排器 fh_review_dispatch.py

把 init_postrun_review.py 生成的逐目标复核工作区，变成子代理可执行的批次文件，
并把 verdict 聚合回 findings_ledger.csv / review_ledger.csv / target_review_queue.csv。

设计要点（W5 已统一的契约，勿改）：
- 状态词 9 值枚举（与 fh skill / 配方A 完全一致）：
  pending|confirmed|rejected|duplicate|out_of_scope|needs_login|approval_required|blocked|accepted_risk
- 工作区 = <run_dir>/postrun_review/（target_review_queue.csv + target_reviews/ + review_ledger.csv + findings_ledger.csv）
- 批次文件自包含：子代理不需要读 fh/SKILL.md 也能干活
- 全程零网络请求，纯本地文件操作

用法：
  python tools/fh_review_dispatch.py --run-dir runs/20260820_114704_one_click_full_weak --prepare [--batch-size 8]
  python tools/fh_review_dispatch.py --run-dir runs/20260820_114704_one_click_full_weak --aggregate
  python tools/fh_review_dispatch.py --run-dir runs/20260820_114704_one_click_full_weak --status
  python fh_review_dispatch.py --run-dir <run> --recommend [--top 5]   # 复核收尾：推荐单目标深挖清单
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

CST = timezone(timedelta(hours=8))

VERDICT_ENUM = [
    "pending", "confirmed", "rejected", "duplicate", "out_of_scope",
    "needs_login", "approval_required", "blocked", "accepted_risk",
]
# verdict JSON 必备字段（batch 指令里也写了一份，双端对齐）
VERDICT_FIELDS = {
    "review_order": int,
    "target_id": str,
    "host": str,
    "disposition": VERDICT_ENUM,
    "confidence": float,          # 0.0-1.0
    "basis": str,                 # 卷宗内证据 "文件路径:行号" 或明确描述
    "next_action": str,           # 空串或建议动作
    "fp_pattern": str,            # rejected 时可空：误报特征，进 fp_memory
    "source_status": dict,        # 可选：{源文件名: status} 回填 review_ledger
}
VERDICT_REQUIRED = ["review_order", "host", "disposition", "confidence", "basis"]

QUEUE_COLS = [
    "target_id", "review_order", "priority", "value_score", "host", "base_url",
    "representative_url", "run_dirs", "categories", "signals", "source_files",
    "safe_readonly_plan", "approval_gates", "rate_limit", "status", "disposition",
    "evidence_paths", "notes",
]
FINDINGS_COLS = [
    "finding_id", "status", "run_dir", "source_item_id", "target", "url_or_path",
    "category", "title", "impact", "permission_level", "evidence_paths", "video_time",
    "cleanup", "retest", "notes",
]
FINDINGS_HEADER = ",".join(FINDINGS_COLS)

PRIORITY_WEIGHT = {"P0": 100, "P1": 60, "P2": 25, "P3": 10}


def now_iso() -> str:
    return datetime.now(CST).isoformat(timespec="seconds")


def load_queue(run_dir: Path) -> list[dict]:
    q = run_dir / "postrun_review" / "target_review_queue.csv"
    if not q.is_file():
        sys.exit(f"[!] 未找到复核工作区 {q}；先运行 scripts/init_postrun_review.py 或 fh skill 的同名脚本")
    with q.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def save_queue(run_dir: Path, rows: list[dict]) -> None:
    q = run_dir / "postrun_review" / "target_review_queue.csv"
    with q.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=QUEUE_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def find_dossier(ws: Path, order: str, host: str) -> Path | None:
    """卷宗定位：兼容 {order}_{host}.md 与零填充 {order:04d}_{host}.md，再 glob 兜底。"""
    tdir = ws / "target_reviews"
    cands = [tdir / f"{order}_{host}.md", tdir / f"{int(order):04d}_{host}.md"]
    for c in cands:
        if c.is_file():
            return c
    for p in sorted(tdir.glob(f"*_{host}.md")) if tdir.is_dir() else []:
        if p.stem.split("_", 1)[0].lstrip("0") == order.lstrip("0"):
            return p
    return None


def batch_instruction(dossier: Path | None, order: str, host: str) -> str:
    """批次文件里每个目标的指令块（自包含：verdict schema 原文 + 输出路径）。"""
    dossier_line = (f"- 卷宗：{dossier}（先完整读它，不要发任何网络请求）" if dossier
                    else "- 卷宗：缺失 → disposition 直接 blocked，basis 写“卷宗缺失，无法复核”")
    return f"""### 目标 {order} · {host}
{dossier_line}
- 完成卷宗 checklist：scope / 源文件 / 类别信号 / 安全只读计划 / 审批门 / 证据 / disposition / cleanup / retest
- 把判定写入 verdicts/{order}.json，schema 如下（UTF-8，一字段不缺）：

```json
{{
  "review_order": {order},
  "target_id": "<卷宗内 target_id>",
  "host": "{host}",
  "disposition": "pending|confirmed|rejected|duplicate|out_of_scope|needs_login|approval_required|blocked|accepted_risk 九值之一",
  "confidence": 0.0,
  "basis": "卷宗内证据（文件路径:行号 或 明确描述），confirmed 必须有确定性证据，证据不足降级 rejected/blocked/needs_login",
  "next_action": "",
  "fp_pattern": "仅 rejected 时可填：误报特征一句话（进 fp_memory 供下轮排重），其余留空",
  "source_status": {{"<源文件名>": "reviewed|skipped"}},
  "family_dispositions": {{"api": "...", "xss": "...", "sqli": "...", "product": "...", "exposure": "..."}}  // 可选但推荐：各候选家族的分别结论，聚合后进 TOP_人工复核
}}
```
"""


def cmd_prepare(run_dir: Path, batch_size: int) -> None:
    rows = load_queue(run_dir)
    ws = run_dir / "postrun_review"
    verdicts_dir = ws / "verdicts"
    verdicts_dir.mkdir(exist_ok=True)
    batches_dir = ws / "review_batches"
    batches_dir.mkdir(exist_ok=True)

    pending_rows = [r for r in rows if (r.get("disposition") or "pending") == "pending"]
    already = {p.stem for p in verdicts_dir.glob("*.json")}
    todo = [r for r in pending_rows if r["review_order"] not in already]
    # 卫生过滤：模板占位域/保留 TLD 不出批次（历史队列可能已被占位域污染）
    import re as _re
    _ph = _re.compile(r"(^|\.)(example|invalid|test|localhost|local|placeholder|replace[-_]me)(\.|$)", _re.I)
    _dirty = [r for r in todo if _ph.search(r.get("host") or "")]
    if _dirty:
        print(f"[!] 过滤 {len(_dirty)} 个占位域目标（不进批次）：" + ", ".join(r.get("host") or "?" for r in _dirty))
        todo = [r for r in todo if r not in _dirty]

    total = len(rows)
    done = total - len(todo)
    print(f"[*] 队列 {total} 目标；已有 disposition 或已有 verdict {done}；待出批次 {len(todo)}")

    if not todo:
        nxt = _next_pending_order(rows)
        print(f"[=] 无待办。下一个未审 review_order={nxt}")
        return

    n_batches = 0
    for bi in range(0, len(todo), batch_size):
        chunk = todo[bi:bi + batch_size]
        idx = bi // batch_size + 1
        bno = f"batch_{idx:03d}"
        bpath = batches_dir / f"{bno}.md"
        if bpath.exists():
            print(f"[=] {bno}.md 已存在，跳过（幂等）")
            continue
        n_batches += 1
        lines = [
            f"# 复核批次 {bno}",
            "",
            f"- 生成：fh_review_dispatch.py --prepare · {now_iso()}",
            f"- 本批 {len(chunk)} 个目标。**一个会话只做这一批**；上下文到预算线（~12万 token，小窗口按 70%）立即收尾，剩余目标留给下个会话。",
            "- 全程零网络请求：判断只依据卷宗与盘上文件；原始响应只引 \"文件路径:行号\"。",
            "- confirmed 必须有卷宗内确定性证据；证据不足一律降级，不硬凑。",
            "",
            "## 目标清单",
            "",
        ]
        for r in chunk:
            order = r["review_order"]
            host = r.get("host", "")
            dossier = find_dossier(ws, order, host)
            lines.append(f"- {order} · {host} · 优先级 {r.get('priority','')} · 卷宗 {'存在' if dossier else '缺失(跳过并在 verdict notes 说明)'}")
        lines.append("")
        lines.append("## 逐目标指令")
        lines.append("")
        for r in chunk:
            order = r["review_order"]
            host = r.get("host", "")
            dossier = find_dossier(ws, order, host)
            lines.append(batch_instruction(dossier, order, host))
        lines.append("## 完成后")
        lines.append("")
        lines.append(f"本批全部 verdict 写入 `{verdicts_dir}` 后，运行：")
        lines.append(f"`python tools/fh_review_dispatch.py --run-dir {run_dir} --aggregate`")
        (batches_dir / f"{bno}.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"[+] 已生成 {n_batches} 个批次文件 → {batches_dir}")
    print(f"[+] verdict 输出目录：{verdicts_dir}")
    nxt = todo[0]["review_order"] if todo else _next_pending_order(rows)
    print(f"[*] 下一个未审 review_order={nxt}")


def _next_pending_order(rows: list[dict]) -> str:
    for r in rows:
        if (r.get("disposition") or "pending") == "pending":
            return r["review_order"]
    return "-（全部已有 disposition）"


def _validate_verdict(data: dict, queue_by_order: dict) -> tuple[bool, str]:
    try:
        order = str(int(data.get("review_order")))
    except (TypeError, ValueError):
        return False, "review_order 缺失或非整数"
    if order not in queue_by_order:
        return False, f"review_order={order} 不在队列"
    disp = data.get("disposition")
    if disp not in VERDICT_ENUM:
        return False, f"disposition={disp!r} 不在 9 值枚举"
    if disp != "pending":
        for fld in ("confidence", "basis"):
            if not data.get(fld) and data.get(fld) != 0:
                return False, f"缺少 {fld}"
        try:
            if not (0.0 <= float(data["confidence"]) <= 1.0):
                return False, "confidence 超出 [0,1]"
        except (TypeError, ValueError):
            return False, "confidence 非数值"
        if disp == "confirmed" and len(str(data.get("basis", "")).strip()) < 10:
            return False, "confirmed 的 basis 过短（需确定性证据描述）"
    return True, ""


def cmd_aggregate(run_dir: Path) -> None:
    rows = load_queue(run_dir)
    ws = run_dir / "postrun_review"
    verdicts_dir = ws / "verdicts"
    queue_by_order = {r["review_order"]: r for r in rows}
    row_by_order = {r["review_order"]: r for r in rows}

    findings_path = ws / "findings_ledger.csv"
    if not findings_path.is_file():
        findings_path.write_text(FINDINGS_HEADER + "\n", encoding="utf-8-sig")

    fp_path = Path("knowledge_base/fp_memory.jsonl")
    if not fp_path.parent.is_dir():
        fp_path = ws / "fp_memory.jsonl"

    verdict_files = sorted(verdicts_dir.glob("*.json")) if verdicts_dir.is_dir() else []
    if not verdict_files:
        print("[=] verdicts/ 无文件；先让子代理按批次文件复核")
        _print_progress(rows)
        return

    invalid_path = ws / "invalid_verdicts.csv"
    applied = skipped = invalid = 0
    fp_added = findings_added = 0
    new_fp_lines: list[str] = []
    verdict_families: dict[str, str] = {}
    # 全库查重集合（KB README 规则：fp_memory 按 host+fp_pattern 去重）
    existing_fp_keys: set = set()
    new_fp_keys: set = set()
    try:
        for _ln in fp_path.read_text(encoding="utf-8").splitlines():
            if not _ln.strip():
                continue
            try:
                _r = json.loads(_ln)
            except json.JSONDecodeError:
                continue
            existing_fp_keys.add(((_r.get("host") or "").strip().lower(), (_r.get("fp_pattern") or "").strip()))
    except FileNotFoundError:
        pass

    existing_orders = set()
    for v in verdict_files:
        try:
            data = json.loads(v.read_text(encoding="utf-8"))
        except Exception as e:
            invalid += 1
            _append_csv(invalid_path, [v.name, f"JSON解析失败: {e}"])
            continue
        ok, err = _validate_verdict(data, queue_by_order)
        if not ok:
            invalid += 1
            _append_csv(invalid_path, [v.name, err])
            continue
        order = str(int(data["review_order"]))
        if order in existing_orders:
            skipped += 1
            continue
        if (row_by_order[order].get("disposition") or "pending") != "pending":
            skipped += 1
            continue
        existing_orders.add(order)
        fam_map = data.get("family_dispositions")
        if isinstance(fam_map, dict) and fam_map:
            verdict_families[order] = " ; ".join(f"{k}:{v}" for k, v in fam_map.items() if v)[:120]

        disp = data["disposition"]
        row = row_by_order[order]
        row["disposition"] = disp
        row["evidence_paths"] = data.get("basis", "") or row.get("evidence_paths", "")
        row["notes"] = (row.get("notes", "") + f" | verdict@{now_iso()} conf={data.get('confidence')}").strip(" |")
        applied += 1

        # review_ledger 回填 source_status
        src_status = data.get("source_status") or {}
        if src_status:
            _update_review_ledger(ws, order, src_status)

        # confirmed → findings_ledger
        if disp == "confirmed":
            fnum = sum(1 for _ in findings_path.open(encoding="utf-8-sig")) - 1
            fid = f"F-{datetime.now(CST).strftime('%Y%m%d')}-{fnum + 1:03d}"
            _append_csv_findings(findings_path, [
                fid, "confirmed", str(run_dir), row.get("target_id", order),
                row.get("host", ""), row.get("representative_url", ""),
                ";".join(filter(None, [row.get("categories", "")])) or "uncategorized",
                f"[AI初判] {row.get('host','')} 候选确认(待人工终审)",
                "待人工评估", "authenticated" if disp == "confirmed" else "unknown",
                data.get("basis", ""), "", "", "", f"confidence={data.get('confidence')} 由 fh_review_dispatch 聚合",
            ])
            findings_added += 1

        # rejected + fp_pattern → fp_memory（按 host+fp_pattern 全库查重，规则与 KB README 一致）
        if disp == "rejected" and data.get("fp_pattern"):
            _fp_host = (data.get("host") or row.get("host", "")).strip().lower()
            _fp_pat = str(data["fp_pattern"]).strip()
            if (_fp_host, _fp_pat) in existing_fp_keys or (_fp_host, _fp_pat) in new_fp_keys:
                print(f"[=] fp_memory 查重跳过：{_fp_host} 已有相同误报特征")
            else:
                new_fp_keys.add((_fp_host, _fp_pat))
                new_fp_lines.append(json.dumps({
                    "ts": now_iso(),
                    "host": data.get("host") or row.get("host", ""),
                    "fp_pattern": _fp_pat,
                    "verdict_basis": f"verdicts/{order}.json basis={data.get('basis','')[:120]}",
                }, ensure_ascii=False))
                fp_added += 1

    save_queue(run_dir, rows)
    if new_fp_lines:
        with fp_path.open("a", encoding="utf-8") as f:
            for ln in new_fp_lines:
                f.write(ln + "\n")

    _write_top_file(ws, rows, verdict_families)
    print(f"[+] 聚合完成：应用 {applied} 条 verdict（跳过 {skipped}，无效 {invalid}→invalid_verdicts.csv）")
    print(f"[+] findings_ledger 新增 {findings_added} 行；fp_memory 新增 {fp_added} 行（→ {fp_path}）")
    _print_progress(rows)


def _print_progress(rows: list[dict]) -> None:
    total = len(rows)
    done = sum(1 for r in rows if (r.get("disposition") or "pending") != "pending")
    nxt = _next_pending_order(rows)
    print(f"[*] 进度：已审 {done}/总数 {total}，下一个未审 review_order={nxt}")


def _append_csv(path: Path, vals: list) -> None:
    new = not path.exists()
    with path.open("a", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["file", "reason"])
        w.writerow(vals)


def _append_csv_findings(path: Path, vals: list) -> None:
    with path.open("a", encoding="utf-8-sig", newline="") as f:
        csv.writer(f).writerow(vals)


def _update_review_ledger(ws: Path, order: str, src_status: dict) -> None:
    p = ws / "review_ledger.csv"
    if not p.is_file():
        return
    with p.open(encoding="utf-8-sig", newline="") as f:
        rrows = list(csv.DictReader(f))
    if not rrows:
        return
    cols = list(rrows[0].keys())
    changed = False
    for rr in rrows:
        if rr.get("order") == order and rr.get("source_file") in src_status:
            st = src_status[rr["source_file"]]
            if st in ("reviewed", "skipped"):
                rr["status"] = st
                changed = True
    if changed:
        with p.open("w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rrows)


def _write_top_file(ws: Path, rows: list[dict], families: dict | None = None) -> None:
    families = families or {}
    done = [r for r in rows if r.get("disposition") not in (None, "", "pending")]
    scored = []
    for r in done:
        w_ = PRIORITY_WEIGHT.get(r.get("priority", ""), 0)
        try:
            w_ += float(r.get("value_score") or 0) / 100.0
        except ValueError:
            pass
        scored.append((w_, r))
    scored.sort(key=lambda t: t[0], reverse=True)
    top = scored[:10]
    lines = [
        "# TOP 人工复核（影响 × 置信度）",
        "",
        f"生成：fh_review_dispatch.py --aggregate · {now_iso()} · 已审 {len(done)}/{len(rows)}",
        "",
        "| review_order | host | disposition | priority | 依据/notes |",
        "|---|---|---|---|---|",
    ]
    for w_, r in top:
        fam = families.get(str(r.get('review_order')), '')
        base_note = (r.get('notes') or r.get('evidence_paths') or '')[:80]
        note = f"{base_note} {fam}".strip()
        lines.append(f"| {r.get('review_order')} | {r.get('host')} | {r.get('disposition')} | {r.get('priority')} | {note} |")
    (ws / "review_batches" / "TOP_人工复核.md").parent.mkdir(exist_ok=True)
    (ws / "review_batches" / "TOP_人工复核.md").write_text("\n".join(lines), encoding="utf-8")




# ---------------------------------------------------------------- recommend

def _count_jsonl_by_host(path: Path) -> dict:
    """统计 jsonl 里按 host/base_url 归属的条数（兼容 host 字段或只有 url/base_url 的行）。"""
    import urllib.parse
    out = {}
    if not path.is_file():
        return out
    for ln in path.read_text(encoding="utf-8").splitlines():
        if not ln.strip():
            continue
        try:
            d = json.loads(ln)
        except json.JSONDecodeError:
            continue
        h = (d.get("host") or "").strip().lower()
        if not h:
            u = d.get("base_url") or d.get("url") or ""
            try:
                h = urllib.parse.urlsplit(u).netloc.lower()
            except Exception:
                continue
        if h:
            out[h] = out.get(h, 0) + 1
    return out


def cmd_recommend(run_dir: Path, top_n: int = 5) -> None:
    """复核收尾：从已审目标里挑出最值得跑单目标网站流程的目标（默认 top 5）。

    选站依据全部来自盘上复核产物（零网络请求）：
    注册可达 > 确认API数量 > 未结高危线索 > 复核判定还有肉 > 老技术栈。
    输出 postrun_review/深挖推荐.md；这是建议清单，最终由操作员逐个拍板。
    """
    rows = load_queue(run_dir)
    ws = run_dir / "postrun_review"
    done = [r for r in rows if (r.get("disposition") or "pending") != "pending"]

    # ---- 盘上数据源（缺失按空处理，不报错） ----
    maq_path = run_dir / "manual_auth_queue.csv"
    reg_hosts = set()
    if maq_path.is_file():
        with maq_path.open(encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f):
                if str(r.get("registration_candidate", "")).strip().lower() == "true":
                    reg_hosts.add((r.get("host") or "").strip().lower())

    api_conf = _count_jsonl_by_host(run_dir / "api_confirmed.jsonl")
    sqli_c = _count_jsonl_by_host(run_dir / "sqli_candidates.jsonl")
    xss_c = _count_jsonl_by_host(run_dir / "xss_candidates.jsonl")
    impact_c = _count_jsonl_by_host(run_dir / "impact_candidates.jsonl")

    # 产品指纹（老技术栈信号）
    old_stack_hosts = set()
    pf_path = run_dir / "product_fingerprints.jsonl"
    OLD_STACK_RE = re.compile(
        r"spring|druid|tomcat|struts|thinkphp|fastjson|log4j|shiro|jenkins|weblogic|jboss|nacos|swagger|knife4j",
        re.I,
    )
    if pf_path.is_file():
        for ln in pf_path.read_text(encoding="utf-8").splitlines():
            if not ln.strip():
                continue
            try:
                d = json.loads(ln)
            except json.JSONDecodeError:
                continue
            hay = " ".join(str(d.get(k, "")) for k in ("host", "product", "fingerprints", "signature", "name"))
            if OLD_STACK_RE.search(hay):
                h = (d.get("host") or "").strip().lower()
                if h:
                    old_stack_hosts.add(h)

    # ---- 逐目标打分 ----
    MAIL_RE = re.compile(r"^(mail|newmail|mx|pop3|imap|smtp|webmail)[.-]", re.I)
    scored = []
    for r in done:
        host = (r.get("host") or "").strip().lower()
        disp = (r.get("disposition") or "").strip().lower()
        if not host:
            continue
        if disp in ("rejected", "out_of_scope", "duplicate", "accepted_risk"):
            continue  # 已证伪/出范围/重复/已接受风险：不再投几小时

        score = PRIORITY_WEIGHT.get(r.get("priority", ""), 0) / 10.0
        reasons = []

        # +40 注册可达：操作员能自助拿 cookie，认证态复核成功率最高
        if host in reg_hosts:
            score += 40
            reasons.append("注册口可达，可自助拿Cookie(+40)")

        # +25 确认 API 数量：业务面真实存在
        n_api = api_conf.get(host, 0)
        if n_api >= 3:
            score += 25
            reasons.append(f"确认API {n_api} 条(+25)")
        elif n_api >= 1:
            score += 15
            reasons.append(f"确认API {n_api} 条(+15)")

        # +20 未结高危线索
        n_sqli, n_xss, n_imp = sqli_c.get(host, 0), xss_c.get(host, 0), impact_c.get(host, 0)
        if n_sqli:
            score += 12
            reasons.append(f"SQLi候选 {n_sqli}(+12)")
        if n_xss:
            add = min(8, 2 * n_xss)
            score += add
            reasons.append(f"XSS候选 {n_xss}(+{add})")
        if n_imp:
            add = min(5, n_imp)
            score += add
            reasons.append(f"影响面候选 {n_imp}(+{add})")

        # +15 复核判定说明认证后还有空间
        if disp in ("needs_login", "approval_required"):
            score += 15
            reasons.append(f"复核判定 {disp}：认证后仍有空间(+15)")
        elif disp == "confirmed":
            score += 20
            reasons.append("已有确认发现，值得继续深挖(+20)")

        # +10 老技术栈
        if host in old_stack_hosts:
            score += 10
            reasons.append("老技术栈/产品指纹(+10)")

        # -30 邮件系统且无注册口：拿不到账号，认证态必卡死
        if MAIL_RE.match(host) and host not in reg_hosts:
            score -= 30
            reasons.append("邮件系统且无注册口，账号难获取(-30)")

        if reasons:
            scored.append((score, host, disp, reasons))

    scored.sort(key=lambda t: t[0], reverse=True)
    top = scored[: max(1, top_n)]

    # ---- 输出 md ----
    lines = [
        "# 单目标深挖推荐（复核收尾产出）",
        "",
        f"生成：fh_review_dispatch.py --recommend · {now_iso()} · 已审 {len(done)}/{len(rows)}",
        "",
        "从已审目标中按以下优先级选出最值得跑**单目标网站流程**的目标（一个目标要几小时，宁缺毋滥）：",
        "注册可达 > 确认API数量 > 未结高危线索 > 复核判定还有肉 > 老技术栈；邮件系统无注册口会被降权。",
        "",
    ]
    if not top:
        lines.append("_没有合适的推荐目标（可能复核还没做完，或全部已证伪）。_")
    else:
        lines.append("| 排名 | host | 复核判定 | 推荐分 | 为什么选它 |")
        lines.append("|---|---|---|---|---|")
        for i, (score, host, disp, reasons) in enumerate(top, 1):
            rr = "；".join(reasons)
            lines.append(f"| {i} | {host} | {disp} | {score:.0f} | {rr} |")
        lines += [
            "",
            "## 怎么用这份清单",
            "",
            "1. 从排名 1 开始逐个拍板：不认可的跳过，认可的才投入几小时。",
            "2. 对认可的目标，到提示词分发员会话拿「网站流程提示词」。",
            "3. 网站流程为单目标模式：scope 直接锚定该 host，跳过子域扫描。",
            "4. 拿 cookie 优先选注册可达的目标；需要登录的先走 01_需要你登录拿Cookie.md 的指引。",
            "",
            "> 推荐只是排序建议，不构成漏洞结论；单目标流程内的写操作仍走审批门。",
        ]
    out = ws / "深挖推荐.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text(chr(10).join(lines), encoding="utf-8")
    print(f"[+] 深挖推荐已写入 {out}")
    for i, (score, host, disp, reasons) in enumerate(top, 1):
        print(f"    {i}. {host} ({disp}, 分数 {score:.0f})")
    _print_progress(rows)


def cmd_status(run_dir: Path) -> None:
    rows = load_queue(run_dir)
    from collections import Counter
    c = Counter((r.get("disposition") or "pending") for r in rows)
    print(f"[*] 队列 {len(rows)} 目标")
    for k in VERDICT_ENUM:
        if c.get(k):
            print(f"    {k:18s} {c[k]}")
    _print_progress(rows)


def main() -> None:
    ap = argparse.ArgumentParser(description="fh 复核子代理编排器（W6）")
    ap.add_argument("--run-dir", required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--prepare", action="store_true")
    g.add_argument("--aggregate", action="store_true")
    g.add_argument("--status", action="store_true")
    g.add_argument("--recommend", action="store_true")
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--top", type=int, default=5, help="--recommend 输出的推荐数量，默认 5")
    a = ap.parse_args()
    run_dir = Path(a.run_dir)
    if a.prepare:
        cmd_prepare(run_dir, a.batch_size)
    elif a.aggregate:
        cmd_aggregate(run_dir)
    elif a.recommend:
        cmd_recommend(run_dir, a.top)
    else:
        cmd_status(run_dir)


if __name__ == "__main__":
    main()
