"""Compatibility export for run and tool paths."""
from project_paths import config_path
from exercise_runtime import (
    ROOT,
    create_run_dir,
    default_tianhu_base,
    expand_template,
    find_executable,
    find_runnable_executable,
)

__all__ = [
    "ROOT", "config_path", "create_run_dir", "default_tianhu_base", "expand_template",
    "find_executable", "find_runnable_executable",
]
