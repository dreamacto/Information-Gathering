# scripts 目录索引

`scripts/` 保存项目维护和本地辅助脚本；生产阶段实现仍暂时保留在仓库根目录，以兼容现有裸导入。

## 子目录约定

- `scripts/maintenance/`：文档/Skill 漂移、清单生成、离线校验和其他仓库维护任务。
- `scripts/imports/`：外部平台、范围和目标清单导入器。
- `scripts/browser/`：浏览器控制台脚本和人工采集辅助。
- `scripts/reporting/`：DOCX、报告渲染和离线报告构建辅助。
- `scripts/butian_toolkit/`：补天平台浏览器控制台工具集。
- `src/authorized_assessment/artifacts/`：已迁移的离线文件完整性与删除审计实现。
- `src/authorized_assessment/analysis/`：已迁移的离线产品和隐私分析实现。

## 当前兼容约定

现有文档、Skill 和桌面入口仍使用以下稳定路径：

```text
scripts/check_doc_drift.py
scripts/check_skill_drift.py
scripts/gen_agent_manifest.py
scripts/gen_sink_lib.py
scripts/init_postrun_review.py
scripts/verify_offline.py
```

这些文件暂不物理移动。新脚本应按上面的职责子目录归类；如果未来移动稳定入口，必须同时更新 `AGENT_MANIFEST.md` 生成器、文档漂移检查和全部 Skill 镜像。
