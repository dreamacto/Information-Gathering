# Agent worker contract

## Manifest

Manifest 登记 `worker_id`、类型（code/analyst/verifier）、版本、能力、输入白名单、输出契约、超时/取消能力和权限。所有 worker 的 `write_scope`、`write_approval`、`write_cursor`、`write_confirmed` 均为 false；网络权限只有 none 或 metadata_only。

## Task envelope

Task 必须带 task/assessment/workflow/phase/correlation/parent lineage、target/context/policy/scope 引用、幂等键、attempt、预算和创建时间。引用只含安全路径与 SHA-256；原文响应、凭证、session 和 HAR 不得进入 envelope。动作限定为 offline/read_only/metadata。

## 三类结果

Code Worker 结果记录事实和 artifact refs；Analyst Worker 必须提供完整游标依据对应的：`facts_used`、`reasoning_summary`、`alternative_explanations`、`hypotheses`、`unknowns`、`coverage`、`not_tested`、`next_hints`。Verifier 结果引用 Code/Analyst result id，并给出 verified、blocked、needs_manual_validation 或 rejected disposition。

只有 Verifier 在双结果门满足时才能把结果升级为可验证结论。`signal` 是线索，`candidate` 进入人工复核，`proven`/confirmed 不能由 Code 或 Analyst 直接产生。

## 错误与权限

Worker error 使用安全错误类、retryable、safe_reason 和 operator action。permission_denied、blocked、scope_conflict 默认不可自动重试。超时/取消不写成功结论。控制面之外的 worker 不可变更 scope、approval、phase cursor，也不可触发高风险或 blocked action。

## 最小安全结果

```json
{
  "result_id": "result_demo",
  "task_id": "task_demo",
  "worker_id": "worker_code_1",
  "worker_type": "code",
  "status": "ok",
  "lineage": {"assessment_id": "asmt_demo", "correlation_id": "corr_demo", "parent_id": null},
  "facts": ["offline artifact summary available"],
  "gate": {"code_result_id": "result_demo", "analyst_result_id": null, "verifier_result_id": null, "dual_result_satisfied": false}
}
```

示例只展示摘要、ID 和门状态；不要把 cookie、token、密码、session key、raw response 或敏感正文替换进来。
