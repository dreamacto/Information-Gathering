"""Local, fail-closed lease store with hashed bearer tokens."""
from __future__ import annotations

import hashlib, json, os, tempfile, time
from pathlib import Path
from typing import Any


def _hash(token: str) -> str:
    if not isinstance(token, str) or not token:
        raise ValueError("token is required")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class LocalLeaseStore:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists(): return {"leases": {}}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(value, dict) or not isinstance(value.get("leases", {}), dict): raise ValueError
            return value
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("invalid lease store") from exc

    def _write(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(value, fh, ensure_ascii=False, sort_keys=True, separators=(",", ":")); fh.flush(); os.fsync(fh.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.exists(name): os.unlink(name)

    @staticmethod
    def _now(now: float | None) -> float: return time.time() if now is None else float(now)
    def inspect(self, resource: str, *, now: float | None = None) -> dict[str, Any]:
        if not isinstance(resource, str) or not resource: return {"ok": False, "status": "rejected", "reason": "invalid_resource"}
        row = self._read().get("leases", {}).get(resource)
        if not row: return {"ok": True, "status": "free", "resource": resource}
        if float(row["expires_at"]) <= self._now(now):
            return {**row, "ok": True, "status": "expired", "resource": resource}
        return {**row, "ok": True, "status": "held", "resource": resource}

    def acquire(self, resource: str, owner: str, ttl_seconds: float, *, token: str, now: float | None = None) -> dict[str, Any]:
        if not isinstance(resource, str) or not resource:
            return {"ok": False, "status": "rejected", "reason": "invalid_resource"}
        if not isinstance(owner, str) or not owner:
            return {"ok": False, "status": "rejected", "reason": "invalid_owner_or_ttl"}
        try:
            ttl = float(ttl_seconds)
        except (TypeError, ValueError):
            return {"ok": False, "status": "rejected", "reason": "invalid_owner_or_ttl"}
        if ttl <= 0 or ttl > 86400:
            return {"ok": False, "status": "rejected", "reason": "invalid_owner_or_ttl"}
        try:
            token_hash = _hash(token)
        except ValueError:
            return {"ok": False, "status": "rejected", "reason": "invalid_token"}
        current = self.inspect(resource, now=now)
        if not current.get("ok"): return current
        if current["status"] == "held": return {"ok": False, "status": "conflict", "reason": "lease_held", "resource": resource}
        started = self._now(now); row = {"owner": owner, "token_hash": token_hash, "acquired_at": started, "expires_at": started + ttl, "status": "held"}
        data = self._read(); data.setdefault("leases", {})[resource] = row; self._write(data)
        return {"ok": True, "resource": resource, **row, "status": "acquired"}

    def renew(self, resource: str, owner: str, ttl_seconds: float, *, token: str, now: float | None = None) -> dict[str, Any]:
        try:
            ttl = float(ttl_seconds)
        except (TypeError, ValueError):
            return {"ok": False, "status": "rejected", "reason": "invalid_ttl"}
        if ttl <= 0 or ttl > 86400: return {"ok": False, "status": "rejected", "reason": "invalid_ttl"}
        data = self._read(); row = data.get("leases", {}).get(resource); current = self.inspect(resource, now=now)
        if not row: return {"ok": False, "status": "not_found", "resource": resource}
        if current["status"] != "held": return {"ok": False, "status": "expired", "resource": resource}
        if row.get("owner") != owner:
            return {"ok": False, "status": "forbidden", "reason": "owner_or_token_mismatch"}
        try:
            token_hash = _hash(token)
        except ValueError:
            return {"ok": False, "status": "forbidden", "reason": "owner_or_token_mismatch"}
        if row.get("token_hash") != token_hash: return {"ok": False, "status": "forbidden", "reason": "owner_or_token_mismatch"}
        row["expires_at"] = self._now(now) + ttl; data["leases"][resource] = row; self._write(data)
        return {"ok": True, "resource": resource, **row, "status": "renewed"}

    def release(self, resource: str, owner: str, *, token: str, now: float | None = None) -> dict[str, Any]:
        data = self._read(); row = data.get("leases", {}).get(resource)
        if not row: return {"ok": False, "status": "not_found", "resource": resource}
        if self.inspect(resource, now=now)["status"] != "held": return {"ok": False, "status": "expired", "resource": resource}
        if row.get("owner") != owner:
            return {"ok": False, "status": "forbidden", "reason": "owner_or_token_mismatch"}
        try:
            token_hash = _hash(token)
        except ValueError:
            return {"ok": False, "status": "forbidden", "reason": "owner_or_token_mismatch"}
        if row.get("token_hash") != token_hash: return {"ok": False, "status": "forbidden", "reason": "owner_or_token_mismatch"}
        del data["leases"][resource]; self._write(data)
        return {"ok": True, "status": "released", "resource": resource}

    get = inspect
    def __enter__(self): return self
    def __exit__(self, *_): return False

LeaseStore = LocalLeaseStore
