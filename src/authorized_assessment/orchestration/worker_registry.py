"""Deterministic in-process registry for offline fake workers."""
from __future__ import annotations
from threading import RLock
from typing import Callable, Mapping
from .worker_manifest import WorkerManifest, manifest_from_dict, validate_manifest

class WorkerRegistry:
    def __init__(self):
        self._lock=RLock(); self._workers={}
    def register(self, manifest: WorkerManifest | Mapping, handler: Callable):
        m=manifest if isinstance(manifest, WorkerManifest) else manifest_from_dict(manifest)
        errors=validate_manifest(m)
        if errors: raise ValueError("manifest rejected: "+"; ".join(errors))
        if not callable(handler): raise TypeError("worker handler must be callable")
        with self._lock:
            if m.worker_id in self._workers: raise ValueError("worker already registered")
            self._workers[m.worker_id]=(m,handler)
        return m
    def unregister(self, worker_id: str):
        with self._lock: return self._workers.pop(worker_id, None) is not None
    def get(self, worker_id: str):
        with self._lock: return self._workers.get(worker_id)
    def manifest(self, worker_id: str):
        item=self.get(worker_id); return None if item is None else item[0]
    def snapshot(self):
        with self._lock: return tuple(self._workers[key][0] for key in sorted(self._workers))
    def clear(self):
        with self._lock: self._workers.clear()

Registry = WorkerRegistry
