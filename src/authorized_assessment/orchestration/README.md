# Orchestration

- `one_click_workflow.py`: single-run workflow launcher.
- `parallel_flow_runner.py`: group-aware batch scheduler.
- `stage_runner.py`: shared synchronous subprocess/logging adapter; it preserves existing stage output and error artifact names.
- `stage_paths.py`: registry of runner-launched scripts and static category/risk/offline metadata; changing a stage location should happen here first.
- `runner_config.py`: shared safe defaults and configuration-path resolution used by the main runner.

The root-level modules remain compatibility entrypoints. Both launchers delegate to the existing `gov_exercise_runner.py` and retain its authorization, rate-control, and approval boundaries.
