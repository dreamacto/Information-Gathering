# Agent state and event model

## State ownership

Assessment 状态由控制面维护：draft → ready → running → completed/blocked → closed。Worker 只能改变自己的结果状态；Analyst 不能写 scope、approval、phase cursor 或 confirmed。Verifier 只根据双结果门给出门控 disposition。

## Cursor and checkpoint

Checkpoint 是单调 sequence 的恢复记录，包含 task/phase、完成/待处理/阻断任务、最后 event/result refs、attempt 和取消状态。写入必须原子替换；它不是 approval，也不是 finding confirmation。WZ 只使用 `phase_status.json`，XCX 只使用 `phase_status.miniapp.json`。

恢复时先验证 policy、scope、上下文 source hashes 和 cursor stream；缺失或漂移 fail-closed。跨 workflow 的 cursor、旧历史或未验证 lead 不能静默继承。

## Events

事件以 `event_id`、类型、producer、correlation/parent、aggregate sequence、幂等键和脱敏 summary 追加。事件 payload 只能是路径、hash 或安全摘要。重复事件以幂等键识别为 replayed；重放只重建本地状态，不执行写操作。

## Approval

审批同时要求脚本审批门和会话内人工确认。两者任一缺失，decision 不能为 approved；blocked_actions 永远不能通过 approval。审批过期、撤销或 scope 冲突立即阻断。

## Metrics and evidence

Metric event 保留窗口、单位、脱敏维度、source refs、dedup/retry lineage 和质量状态。历史派生指标不得当作当前事实。证据按 signal/candidate/proven 分级；没有 Code、Analyst 和 Verifier 三者，不能进入 proven。

## Fail-closed conditions

范围不明确、授权缺失、服务停止条件、权限拒绝、敏感字段/路径、非法 DAG、缺结果、超时或取消都必须记录 blocked/needs_manual_validation，并留下 operator_tasks；不伪造 complete。
