# 旧脚本与高风险入口索引

这些脚本保留是为了兼容历史工作，不作为当前主流程入口。新手优先使用桌面一键脚本或 `gov_exercise_runner.py`。

| 脚本 | 风险/问题 | 建议 |
| --- | --- | --- |
| `blind_exploit.py` | 名称和用途偏主动利用 | 不进默认流程，单目标审批后再评估 |
| `post_exploitation.py` | 后渗透动作风险高 | 不作为演练常规流程 |
| `lateral_movement.py` | 横向移动风险高 | 不作为演练常规流程 |
| `vuln_dispatcher.py` | 可能调度多类验证 | 用产品漏洞候选队列替代 |
| `scanner.py` | 老入口，边界和限速不清晰 | 用 `gov_exercise_runner.py` 替代 |
| `pentest_pipeline.py` | 老流程入口，容易和新流程混淆 | 用桌面一键脚本替代 |
| `pentest_controller.py` | 老控制器，边界不如新主流程清楚 | 用桌面一键脚本替代 |
| `credential_spray.py` | 凭证喷洒高风险 | 默认禁用；弱口令只走人工门控流程 |
| `weak_passwd_scanner.py` | 老弱口令扫描入口 | 用 `weak_credential_review.py` 的低频显式流程替代 |

当前推荐主线：

```text
目标文件 -> gov_exercise_runner.py / 桌面一键脚本 -> runs\<本轮目录>\00_重要_人工复核入口 -> reports\screenshot_queue.md -> evidence_builder.py
```

不要从旧脚本开始新任务，除非你已经确认它的请求速率、目标范围、输出内容和演练授权边界。
