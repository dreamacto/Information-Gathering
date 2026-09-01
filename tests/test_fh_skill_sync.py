# -*- coding: utf-8 -*-
"""tests/test_fh_skill_sync.py —— batch14_3+14_4：规格 §11/§3.2/§8 同步测试。

规格依据（docs/AI_IMPLEMENTATION_SPEC_SECURITY_COVERAGE_AND_FINDING_QUALITY.md）：
- §11（2166-2256 行）：结论模板/四问否决/细微发现处置/最小链条写入 6 配方与
  3 个 workflow SKILL；
- §3.2（732-756 行）：docs/RULE_PRECEDENCE.md 在所有 workflow Skill 与 prompt 中
  被引用（单一事实源，正文不复制）；
- §8（1916-1977 行）：fh 复核链路字段/顺序/判定规则（batch14_4 扩展本文件）。

本文件只做文本锚点与结构断言，纯离线。模板块九行与规格 2183-2205 行逐字一致
（枚举层不自行改写——呈现层词汇与判定落盘词表 review_statuses 的边界见卡片留痕）。
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

RECIPES = [
    "prompts/配方A_复盘会话.md",
    "prompts/配方B_规划会话.md",
    "prompts/配方C_单目标深挖.md",
    "prompts/配方D_逻辑漏洞工作坊.md",
    "prompts/配方F_白盒研判.md",
    "prompts/配方Z_全流程验收.md",
]
SKILLS = [
    ".agents/skills/fh/SKILL.md",
    ".agents/skills/wz/SKILL.md",
    ".agents/skills/xcx/SKILL.md",
]

TEMPLATE_LINES = [
    "对象类型：signal | candidate | confirmed | inconclusive",
    "授权状态：confirmed | confirmation_required | blocked",
    "可触达性：reachable | unverified | unreachable",
    "复现状态：reproducible | partial | not_reproduced",
    "影响类别：none | low | medium | high | critical",
    "影响对象：用户/租户/业务对象/权限/数据/网络边界/服务可用性",
    "证据完整性：complete | partial | missing",
]
FOUR_QUESTIONS = [
    "1. 是否有明确的授权资产和允许的测试动作？",
    "2. 是否有真实可触达的端点、功能或数据流？",
    "3. 是否有可重复的异常行为或越权结果？",
    "4. 是否能说明对企业造成了非琐碎的安全影响并提供证据？",
]
PRECEDENCE_REF = "docs/RULE_PRECEDENCE.md"
PRECEDENCE_CONTRACT = "contracts/rule_precedence.json"
TEMPLATE_HEADING = "## AI 结论模板（实施规格 §11"


def _text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_conclusion_template_present_in_all_nine_files():
    for rel in RECIPES + SKILLS:
        t = _text(rel)
        assert TEMPLATE_HEADING in t, f"{rel}: missing template heading"
        for line in TEMPLATE_LINES:
            assert line in t, f"{rel}: missing template line {line!r}"
        for q in FOUR_QUESTIONS:
            assert q in t, f"{rel}: missing four-question line {q!r}"
        assert "为什么不升级为漏洞" in t, f"{rel}: missing signal-handling requirement"
        assert "推测" in t and "candidate" in t, f"{rel}: missing minimal-chain rule"


def test_rule_precedence_referenced_in_all_nine_files():
    for rel in RECIPES + SKILLS:
        t = _text(rel)
        assert PRECEDENCE_REF in t, f"{rel}: missing RULE_PRECEDENCE reference"
        assert PRECEDENCE_CONTRACT in t, f"{rel}: missing rule_precedence contract reference"
        assert "context_conflicts" in t, f"{rel}: missing context_conflicts requirement"


def test_template_enums_match_spec_verbatim():
    """模板九行枚举与规格 §11.1 原文逐字一致（防实现侧改写枚举层）。"""
    spec = _text("docs/AI_IMPLEMENTATION_SPEC_SECURITY_COVERAGE_AND_FINDING_QUALITY.md")
    for line in TEMPLATE_LINES:
        assert line in spec, f"template line not verbatim in spec: {line!r}"


def test_recipe_template_placed_before_output_contract_or_boundary():
    """配方模板块落点：Z 在"与日常模式的边界"前，其余在"输出契约"前（设计卡片留痕）。"""
    for rel in RECIPES:
        t = _text(rel)
        tpl_at = t.find(TEMPLATE_HEADING)
        assert tpl_at != -1, f"{rel}: no template"
        if rel.endswith("配方Z_全流程验收.md"):
            boundary_at = t.find("\n## 与日常模式的边界\n")
            assert boundary_at != -1
            assert tpl_at < boundary_at, f"{rel}: template must precede boundary section"
        else:
            oc_at = t.find("\n## 输出契约\n")
            assert oc_at != -1
            assert tpl_at < oc_at, f"{rel}: template must precede output contract"




# ---------------------------------------------------------------------------
# 规格 §8（batch14_4）：fh 复核链路字段/顺序/判定规则
# ---------------------------------------------------------------------------

INIT_SCRIPT = "scripts/init_postrun_review.py"
DISPATCH_SCRIPT = "fh_review_dispatch.py"
SKILL_INIT_COPY = ".agents/skills/fh/scripts/init_postrun_review.py"

SPEC_82_FIELDS = [
    "finding_id", "candidate_id", "asset_type", "vulnerability_family", "impact_class",
    "quality_status", "recommended_workflow", "recommended_phase", "blocked_reason",
    "next_action", "owner", "sla", "last_seen", "evidence_ref",
]
LEGACY_15 = [
    "finding_id", "status", "run_dir", "source_item_id", "target", "url_or_path",
    "category", "title", "impact", "permission_level", "evidence_paths", "video_time",
    "cleanup", "retest", "notes",
]
NEW_13 = [
    "candidate_id", "asset_type", "vulnerability_family", "impact_class",
    "quality_status", "recommended_workflow", "recommended_phase", "blocked_reason",
    "next_action", "owner", "sla", "last_seen", "evidence_ref",
]
ORDER_83 = [
    "run_quality_gate", "scope_reconciliation", "candidate_deduplication",
    "source_coverage_check", "authentication_queue_review", "authorization_queue_review",
    "injection_queue_review", "ssrf_queue_review", "product_queue_review",
    "miniapp_queue_review", "evidence_gate", "report_lifecycle", "cleanup_audit",
]
RULES_84 = [
    "INCONCLUSIVE",
    "Fixed-path signals never enter the main vulnerability queue",
    "automatically demoted to `needs_manual_validation`",
    "keeping the first-seen and last-validated timestamps",
    "never raises severity by itself",
]


def _findings_fields_from_source(rel: str) -> list[str]:
    """从源码文本提取 FINDING_FIELDS/FINDINGS_COLS 字面量（不导入模块——脚本
    self-contained 设计，导入会执行 pandas 等重依赖；AST 字面量提取更稳）。"""
    import ast as _ast

    tree = _ast.parse(_text(rel))
    for node in tree.body:
        if isinstance(node, _ast.Assign):
            targets = [getattr(tg, "id", "") for tg in node.targets]
            if "FINDING_FIELDS" in targets or "FINDINGS_COLS" in targets:
                return [elt.value for elt in node.value.elts]
    raise AssertionError(f"{rel}: FINDING_FIELDS/FINDINGS_COLS literal not found")


def test_findings_fields_match_spec_82():
    """init FINDING_FIELDS 与 dispatch FINDINGS_COLS 均 = 15 旧列 + 13 规格新列，
    规格 8.2 十四字段全部在场且新列相对顺序与规格一致。"""
    for rel in (INIT_SCRIPT, DISPATCH_SCRIPT):
        cols = _findings_fields_from_source(rel)
        assert cols == LEGACY_15 + NEW_13, f"{rel}: 28-col layout drifted"
        assert all(f in cols for f in SPEC_82_FIELDS), f"{rel}: spec-8.2 field missing"
        spec_only_order = [c for c in cols if c in SPEC_82_FIELDS]
        assert spec_only_order == [
            "finding_id",
            "candidate_id",
            "asset_type",
            "vulnerability_family",
            "impact_class",
            "quality_status",
            "recommended_workflow",
            "recommended_phase",
            "blocked_reason",
            "next_action",
            "owner",
            "sla",
            "last_seen",
            "evidence_ref",
        ], f"{rel}: spec-8.2 field order drifted"


def test_init_postrun_review_copies_are_unified():
    """根 scripts 版与 skill scripts 版 init_postrun_review.py 字节一致（batch14_4
    统一为 skill 版 verdicts/ 语义），且 skill 镜像 copy 同步。"""
    root = ROOT / INIT_SCRIPT
    skill = ROOT / SKILL_INIT_COPY
    assert root.is_file() and skill.is_file()
    assert root.read_bytes() == skill.read_bytes(), "init_postrun_review copies drifted"
    for mr in (".claude", ".opencode"):
        m = ROOT / mr / "skills" / "fh" / "scripts" / "init_postrun_review.py"
        assert m.read_bytes() == skill.read_bytes(), f"mirror drift: {mr}"
    ts = skill.read_text(encoding="utf-8")
    assert '    "evidence_ref",\n' in ts.replace("\\n", "\n") or '"evidence_ref"' in ts


def test_fh_skill_has_run_level_aggregation_order():
    """fh SKILL.md 含规格 8.3 run 级聚合顺序节，13 步逐字有序。"""
    t = _text(SKILLS[0])
    heading_at = t.find("## Run-Level Aggregation Order (spec 8.3)")
    assert heading_at != -1, "8.3 heading missing"
    block = t[heading_at : t.find("## Review Order", heading_at)]
    positions = [block.find(step) for step in ORDER_83]
    assert all(pos != -1 for pos in positions), f"8.3 step missing: {[s for s, p in zip(ORDER_83, positions) if p == -1]}"
    assert positions == sorted(positions), "8.3 steps out of order"
    assert "## Run-Level Aggregation Order (spec 8.3)" in _text(".claude/skills/fh/SKILL.md")
    assert "## Run-Level Aggregation Order (spec 8.3)" in _text(".opencode/skills/fh/SKILL.md")


def test_fh_playbook_has_spec_84_verdict_rules():
    """review-playbook.md 含规格 8.4 五条判定规则（关键词级），镜像同步。"""
    for rel in (
        ".agents/skills/fh/references/review-playbook.md",
        ".claude/skills/fh/references/review-playbook.md",
        ".opencode/skills/fh/references/review-playbook.md",
    ):
        t = _text(rel)
        assert "## Verdict rules (spec 8.4)" in t, f"{rel}: 8.4 section missing"
        for kw in RULES_84:
            assert kw in t, f"{rel}: 8.4 rule missing: {kw!r}"


def test_output_map_documents_findings_field_map():
    """output-map.md 含 8.2 字段映射注（evidence_ref/evidence_paths 并存语义）。"""
    for rel in (
        ".agents/skills/fh/references/output-map.md",
        ".claude/skills/fh/references/output-map.md",
        ".opencode/skills/fh/references/output-map.md",
    ):
        t = _text(rel)
        assert "Findings ledger field map (spec 8.2" in t
        assert "evidence_ref" in t and "evidence_paths" in t
        assert "candidate_id" in t and "quality_status" in t


def test_postrun_review_skill_delegates_field_contract():
    """postrun-review SKILL.md 委托 fh skill 为 8.2/8.3/8.4 权威契约。"""
    t = _text(".agents/skills/postrun-review/SKILL.md")
    assert "规格 8.2" in t and "规格 8.3" in t and "规格 8.4" in t
    assert "references/review-playbook.md" in t

def test_skill_template_placements_and_precedence_anchor():
    """SKILL 模板块落点与 §3.2 引用锚点：fh 在 First Files 前，wz/xcx 在 Session
    scope 前；§3.2 引用在各 SKILL 硬约束 intro 行后（规则 0 编号）。"""
    for rel, follower in (
        (SKILLS[0], "\n## First Files To Read\n"),
        (SKILLS[1], "\n## Session scope (stage gate)\n"),
        (SKILLS[2], "\n## Session scope (stage gate)\n"),
    ):
        t = _text(rel)
        intro_at = t.find("These override every other instruction in this skill.")
        assert intro_at != -1, f"{rel}: intro missing"
        ref_at = t.find("0. **规则优先级**")
        assert ref_at != -1, f"{rel}: precedence ref missing"
        assert ref_at > intro_at, f"{rel}: precedence ref must follow intro"
        tpl_at = t.find(TEMPLATE_HEADING)
        follower_at = t.find(follower)
        assert tpl_at != -1 and follower_at != -1
        assert intro_at < ref_at < tpl_at < follower_at, f"{rel}: bad section ordering"
