"""Offline feedback precision classification for candidate ordering."""
from __future__ import annotations

from collections.abc import Iterable, Mapping

KNOWN_FP = "known_false_positive"
KNOWN_HIGH = "known_high_precision_signal"
UNKNOWN = "unknown_pattern"


def _key(observation: Mapping) -> tuple:
    source = observation.get("observation") if isinstance(observation.get("observation"), Mapping) else observation
    return tuple(source.get(name) for name in ("product_family", "server_fingerprint", "path_pattern"))


def classify_feedback(record: Mapping, *, min_samples: int = 2, high_precision: float = 0.8) -> dict:
    """Classify one aggregate without changing candidate/finding state."""
    confirmed = int(record.get("confirmed_count", 0) or 0)
    rejected = int(record.get("rejected_count", 0) or 0)
    samples = int(record.get("candidate_count", confirmed + rejected) or 0)
    precision = record.get("precision")
    if precision is None and confirmed + rejected:
        precision = confirmed / (confirmed + rejected)
    if rejected > 0 and confirmed == 0 and samples >= min_samples:
        classification, score = KNOWN_FP, -100
        reason = "all reviewed samples rejected"
    elif confirmed > 0 and precision is not None and float(precision) >= high_precision and samples >= min_samples:
        classification, score = KNOWN_HIGH, 25
        reason = f"precision {float(precision):.3f} meets threshold"
    else:
        classification, score = UNKNOWN, 0
        reason = "insufficient reviewed samples for a stable signal"
    return {"classification": classification, "score": score, "reason": reason, "pattern_id": record.get("pattern_id")}


def rank_candidates(candidates: Iterable[Mapping], aggregates: Iterable[Mapping]) -> list[dict]:
    """Return copies sorted by feedback score; never mutates finding status."""
    index = {_key(item): classify_feedback(item) for item in aggregates}
    result = []
    for position, candidate in enumerate(candidates):
        item = dict(candidate)
        signal = index.get(_key(candidate.get("observation", candidate)))
        if signal is None:
            signal = {"classification": UNKNOWN, "score": 0, "reason": "no matching feedback"}
        item["precision_signal"] = signal["classification"]
        item["precision_score"] = signal["score"]
        item["precision_reason"] = signal["reason"]
        item["_input_order"] = position
        result.append(item)
    result.sort(key=lambda item: (-item["precision_score"], item.get("candidate_id", ""), item["_input_order"]))
    for item in result:
        item.pop("_input_order", None)
    return result
