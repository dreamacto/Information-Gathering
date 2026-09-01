# RULE_PRECEDENCE · 规则优先级（唯一事实源）

> 本文件是 `contracts/rule_precedence.json` 的人读副本，两者由 `tests/test_rule_precedence.py` 强制同步。
> 所有 workflow Skill（fh/wz/xcx 等）和 prompts 引用优先级时，必须引用本文件，不得各自另立优先级。

## 优先级顺序（高 → 低）

1. 系统/开发者指令
2. AGENTS.md
3. ROE.md 与当前授权证据
4. 当前 engagement scope、approval 和 stop 状态
5. 当前 workflow Skill（fh/wz/xcx 等）
6. 当前 phase contract/schema
7. gov_exercise_config.json
8. tool_strategy.json 与 tool registry
9. prompts 和实施规格
10. 当前 run 的历史派生结果与 knowledge_base
11. 外部方法学资料

## 规则冲突处理

- 高层规则覆盖低层规则（`override_direction: higher_rank_overrides_lower_rank`）。
- 历史 run、知识库和外部资料不能覆盖当前授权、scope、审批和停止条件。
- 冲突不得由 AI 静默选择，必须写入 `context_conflicts`（context_snapshot 字段，见 `contracts/context_snapshot_schema.json`）。
- 当前 scope 不明确时只能进入 `confirmation_required` 或 `blocked`，不能继续主动测试。

## 使用方式

- AI 会话开工前按 `docs/CONTEXT_LOADING_MAP.yaml` 分层加载（L0/L1/L2/L3），不得全文读取项目。
- 冲突判定所需的原文回读顺序：先读本表更高级别的源，再读低级别源；回读结果记入 `context_conflicts`。
