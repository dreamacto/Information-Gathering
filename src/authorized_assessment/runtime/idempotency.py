"""Offline operation idempotency records; payloads and secrets are never stored."""
from __future__ import annotations
import hashlib, json, os, tempfile, time
from pathlib import Path
from typing import Any


def normalize_operation_key(key: str) -> str:
    if not isinstance(key, str): raise ValueError("operation key must be text")
    if any(c in "\r\n\t" for c in key): raise ValueError("invalid operation key")
    key = key.strip()
    if not key or len(key) > 256 or any(c.isspace() and c != " " for c in key): raise ValueError("invalid operation key")
    return key


def fingerprint(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class IdempotencyStore:
    def __init__(self, path: str | os.PathLike[str]): self.path = Path(path)
    def _read(self):
        if not self.path.exists(): return {"operations": {}}
        try:
            v=json.loads(self.path.read_text(encoding="utf-8")); assert isinstance(v,dict) and isinstance(v.get("operations",{}),dict); return v
        except Exception as exc: raise ValueError("invalid idempotency store") from exc
    def _write(self, v):
        self.path.parent.mkdir(parents=True, exist_ok=True); fd,n=tempfile.mkstemp(prefix=self.path.name+".",dir=self.path.parent)
        try:
            with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as f: json.dump(v,f,ensure_ascii=False,sort_keys=True,separators=(",",":")); f.flush(); os.fsync(f.fileno())
            os.replace(n,self.path)
        finally:
            if os.path.exists(n): os.unlink(n)
    def inspect(self, key: str):
        key=normalize_operation_key(key); row=self._read()["operations"].get(key)
        return None if row is None else {**row,"operation_key":key,"status":"replayable"}
    def record(self, key: str, request: Any, *, result_id: str | None = None, status: str="accepted", summary: str | None = None, path_ref: str | None = None, now: float | None = None):
        key=normalize_operation_key(key); fp=fingerprint(request); data=self._read(); old=data["operations"].get(key)
        if status not in {"accepted","rejected","blocked","failed"}: raise ValueError("invalid status")
        if old:
            if old["fingerprint"] == fp: return {**old,"operation_key":key,"status":"replayed","ok":True}
            return {"ok":False,"operation_key":key,"status":"conflict","reason":"fingerprint_mismatch"}
        if status not in {"accepted","rejected","blocked","failed"}: return {"ok":False,"status":"rejected","reason":"invalid_status"}
        row={"fingerprint":fp,"result_id":result_id,"result_status":status,"summary":summary,"path_ref":path_ref,"created_at":time.time() if now is None else float(now)}
        data["operations"][key]=row; self._write(data); return {**row,"operation_key":key,"status":status,"ok":True}
    accept=record
    get=inspect
