"""Compatibility export for canonical target parsing."""
from exercise_runtime import (
    Target,
    domain_hint_from_targets,
    is_header_like_target,
    load_targets,
    normalize_url,
    parse_target_line,
    split_target_line,
)

__all__ = [
    "Target", "domain_hint_from_targets", "is_header_like_target", "load_targets",
    "normalize_url", "parse_target_line", "split_target_line",
]
