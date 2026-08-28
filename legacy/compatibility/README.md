# Legacy compatibility

这里记录仍被历史脚本、外部快捷方式或旧流程引用的兼容模块。它们不属于默认生产流程，不应被新代码继续依赖。

当前仍保留在仓库根目录的兼容模块包括：

- `config.py`：旧天狐工具路径注册表；新代码使用 `gov_exercise_config.json` 和 `project_paths.py`。
- `scanner.py`、`batch_runner.py`、`pentest_pipeline.py`、`pentest_controller.py`：旧流程入口。
- `toolkit_integration.py`、`vuln_dispatcher.py`：旧工具调度入口。

这些文件暂不物理移动，因为它们存在裸导入、固定路径和历史命令依赖。迁移时应先增加新包入口，再逐项验证调用方。
