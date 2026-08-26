"""Fail-closed policy checks shared by controlled and legacy entry points."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_BLOCKED_ACTIONS = frozenset({
    "password_spray", "bruteforce", "webshell", "c2", "tunnel",
    "data_export", "destructive_write", "ddos", "social_engineering", "near_field",
})
READ_ONLY_ACTIONS = frozenset({"check", "probe", "passive_discovery", "metadata_read", "offline_review"})


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    outcome: str
    reason: str
    action: str = ""
    target: str = ""
    phase: str = ""
    entrypoint: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class PolicyError(RuntimeError):
    pass


class PolicyEngine:
    """Small, dependency-free policy gate. Missing policy data always denies."""

    def __init__(self, config: dict, workflow: dict | None = None,
                 strategy: dict | None = None, targets: list | None = None,
                 run_dir: Path | None = None, entrypoint: str = "") -> None:
        self.config = config if isinstance(config, dict) else {}
        self.workflow = workflow if isinstance(workflow, dict) else {}
        self.strategy = strategy if isinstance(strategy, dict) else {}
        self.targets = targets or []
        self.run_dir = Path(run_dir) if run_dir else None
        self.entrypoint = entrypoint
        configured = self.config.get("blocked_actions")
        if not isinstance(configured, list) or not all(isinstance(x, str) for x in configured):
            self.blocked_actions = DEFAULT_BLOCKED_ACTIONS
            self.valid = False
        else:
            self.blocked_actions = frozenset(configured) | DEFAULT_BLOCKED_ACTIONS
            self.valid = True
        self._target_keys = {self._target_key(getattr(t, "url", t)) for t in self.targets}

    @staticmethod
    def _target_key(value: object) -> str:
        raw = str(value or "").strip()
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        try:
            port = parsed.port
        except ValueError:
            return ""
        default_port = 443 if parsed.scheme == "https" else 80
        return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}:{port or default_port}{parsed.path or ''}?{parsed.query or ''}"

    @staticmethod
    def _safe_text(value: object, limit: int = 240) -> str:
        text = str(value or "")
        text = re.sub(r"(?i)(authorization|cookie|token|password|secret)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", text)
        return text[:limit]

    def _record(self, decision: PolicyDecision) -> PolicyDecision:
        if self.run_dir:
            path = self.run_dir / "policy_decisions.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True)
            item = decision.to_dict()
            item["target_sha256"] = hashlib.sha256(decision.target.encode()).hexdigest() if decision.target else ""
            item["target"] = self._safe_text(decision.target)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
        return decision

    def _decision(self, allowed: bool, reason: str, *, action: str = "", target: str = "", phase: str = "") -> PolicyDecision:
        return self._record(PolicyDecision(allowed, "allow" if allowed else "deny", reason,
                                            action, target, phase, self.entrypoint))

    def authorize_target(self, url: str, context: dict | None = None) -> PolicyDecision:
        key = self._target_key(url)
        if not self.valid:
            return self._decision(False, "invalid or incomplete policy configuration", target=url)
        if not key:
            return self._decision(False, "target must be an http(s) URL with a valid host", target=url)
        if key not in self._target_keys:
            return self._decision(False, "target is not in the approved target snapshot", target=url)
        return self._decision(True, "target matches approved snapshot", target=url)

    def authorize_action(self, action: str, target: str = "", phase: str = "", context: dict | None = None) -> PolicyDecision:
        action = str(action or "").strip().lower()
        context = context or {}
        if not self.valid:
            return self._decision(False, "invalid or incomplete policy configuration", action=action, target=target, phase=phase)
        if action in self.blocked_actions:
            return self._decision(False, f"blocked action: {action}", action=action, target=target, phase=phase)
        if target:
            target_decision = self.authorize_target(target, context)
            if not target_decision.allowed:
                return self._decision(False, target_decision.reason, action=action, target=target, phase=phase)
        if context.get("requires_approval") and not context.get("approval_confirmed"):
            return self._decision(False, "explicit approval is required", action=action, target=target, phase=phase)
        if action not in READ_ONLY_ACTIONS and not context.get("approval_confirmed"):
            return self._decision(False, "non-read-only action requires explicit approval", action=action, target=target, phase=phase)
        return self._decision(True, "action permitted by policy", action=action, target=target, phase=phase)

    def authorize_tool(self, tool_id: str, capabilities: list[str] | set[str] | None = None,
                       target: str = "", params: list[str] | None = None,
                       context: dict | None = None) -> PolicyDecision:
        context = context or {}
        caps = {str(x).lower() for x in (capabilities or {"unknown"})}
        dangerous = caps & {"unknown", "credential_testing", "rce", "data_export", "tunnel", "persistence", "destructive_write"}
        if dangerous:
            return self._decision(False, f"tool capability requires explicit approved execution: {','.join(sorted(dangerous))}", action="tool", target=target, phase=str(context.get("phase", "")))
        return self.authorize_action("metadata_read", target, str(context.get("phase", "")), context)

    def authorize_command(self, argv: list[str] | tuple[str, ...], tool_id: str = "",
                          context: dict | None = None) -> PolicyDecision:
        context = context or {}
        if not isinstance(argv, (list, tuple)) or not argv or any(not isinstance(x, str) for x in argv):
            return self._decision(False, "commands must use a non-empty argv sequence", action="command")
        if any(x in str(argv) for x in ("&", "|", ";", "`", "$(", "\n", "\r")):
            return self._decision(False, "shell metacharacters are not accepted in command arguments", action="command")
        return self.authorize_action("metadata_read", str(context.get("target", "")), str(context.get("phase", "")), context)


def load_policy_engine(config: dict, workflow: dict | None = None, strategy: dict | None = None,
                       targets: list | None = None, run_dir: Path | None = None,
                       entrypoint: str = "") -> PolicyEngine:
    return PolicyEngine(config, workflow, strategy, targets, run_dir, entrypoint)
