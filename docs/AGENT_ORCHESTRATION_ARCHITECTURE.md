# Agent orchestration architecture

施工表 00 冻结的控制面模型是：`assessment → graph → task → worker → result → checkpoint/event/metric`。控制面拥有授权、scope、approval、phase cursor 和最终 finding 状态；worker 只消费任务并输出受契约约束的本地结果。

## 角色

- **Control plane**：创建 assessment 和 DAG，读取 policy decision，派发 task，维护 checkpoint，写 approval 和 phase cursor。
- **Code Worker**：执行离线或受控只读事实采集，输出事实、artifact refs、错误和覆盖信息。
- **Analyst Worker**：读取完整游标上下文：target-model、coverage、候选/ledger 索引、阶段摘要、artifact refs、未测空间以及 policy/scope 摘要；只输出结构化分析，不改控制面状态。
- **Verifier**：同时消费 Code 与 Analyst 结果，检查授权、可达性、可复现性、影响和证据；缺任一结果或证据不足时只能 blocked/needs_manual_validation。

## 图与任务

Graph 是 DAG。节点可为 task、worker、gate、checkpoint、approval 或 verifier；edge endpoint 必须存在且无环。WZ 节点绑定 `phase_status.json`，XCX 节点绑定 `phase_status.miniapp.json`，不得交叉复用。task envelope 只允许 `offline`、`read_only`、`metadata` 动作；approval ref 是证明已有审批，不是授权授予字段。

每个 task 带 assessment/correlation/parent lineage、幂等键、attempt、预算、取消和上下文/策略引用。相同幂等键不得重复产生外部效果；本施工表的实现只允许本地/只读行为。

## 生命周期与恢复

控制面按 started/completed/failed/cancelled 写事件，使用单调 sequence 的 checkpoint 原子替换恢复。timeout、取消、权限拒绝和 scope 冲突 fail-closed；可重试性由 worker error 明确表达。事件追加式、可幂等重放，但重放永不触发写操作。

## 结果与指标

Code 与 Analyst 结果是双结果门输入；只有 Verifier 可以产生 `disposition=verified`，worker/analyst 不得直接写 `confirmed` 或 `proven`。metric event 只记录脱敏 hash、路径引用和 lineage，历史指标不覆盖当前授权事实。

## 安全边界

契约禁止凭证、session、cookie、token、password、secret、HAR、raw response 和全量敏感数据。blocked_actions 永远覆盖 allow。缺 scope、policy、cursor 或上下文时进入 blocked/confirmation_required，不得凭历史结果推断当前授权。
