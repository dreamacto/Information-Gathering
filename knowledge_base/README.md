# knowledge_base/ 三库说明

> 施工工单 W9 落地物。三个 jsonl 库 + 一个 sink 库（W13 加入），全部追加式、UTF-8、一行一 JSON。
> 消费关系总原则：**脚本只追加，AI 只读取；人负责把 tested_confirmed 回填。**

## 库清单与读写关系

| 库 | 谁写入 | 谁读取 | 何时 |
|---|---|---|---|
| fp_memory.jsonl | fh_review_dispatch.py --aggregate（rejected 且带 fp_pattern 时自动追加）；配方A 复核子代理间接产出 | 配方B 规划会话（排重依据）；metrics_weekly.py（FP 率指标） | 每次复核聚合 / 每轮规划 / 每周度量 |
| vuln_pattern_lib.jsonl | 人工（确认一个漏洞后）；配方E 周度沉淀建议追加 | 配方B（假设模板来源）；配方D（竞态场景模板） | 每次确认漏洞 / 每周沉淀 |
| hypothesis_ledger.jsonl | 配方B 追加 proposed；W7/W8 执行后人工回填 status | 配方B（避免重复提出）；metrics_weekly.py（命中率指标） | 每轮规划 / 每次执行后 |
| sink_lib.jsonl (W13) | 人工维护（模式库，低频更新） | whitebox_triage.py（扫描种子） | 每次白盒扫描 |

## schema（字段定死，勿改字段名）

- fp_memory: `{"ts","host","fp_pattern","verdict_basis"}` —— 与 fh_review_dispatch.py --aggregate 输出完全一致
- vuln_pattern_lib: `{"id","category","business_scene","hypothesis_template","test_recipe","proven_count","last_used"}`
- hypothesis_ledger: `{"id","ts","hypothesis","basis","expected_observable","test_tool","cost","risk","negative_control","status","note"}`，status 枚举 `proposed|approved|tested_confirmed|tested_falsified|dropped`
- sink_lib (W13): `{"category","lang","pattern","severity","note"}`，category 枚举 `sqli|command|path_traversal|ssrf|deserialize|weak_crypto|authz_missing`

## 使用纪律

1. 任何脚本写入前先读全库去重（fp_memory 按 host+fp_pattern，ledger 按 hypothesis 文本）。
2. 人工回填 status 时只改 status 与 note，不动原始字段。
3. 禁止把凭证、内网地址写进任何一库。
