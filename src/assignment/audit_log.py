"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(
        self,
        *,
        user_id: str,
        text: str,
        request_id: str | None = None,
    ):
        key = request_id or user_id

        self._open[key] = {
            "request_id": request_id,
            "user_id": user_id,
            "input": text,
            "timestamp": utc_now_iso(),
            "started_at": time.perf_counter(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        key = request_id or user_id
        pending = self._open.pop(key, None)

        latency_ms = None
        if pending is not None:
            latency_ms = round(
                (time.perf_counter() - pending["started_at"]) * 1000,
                2,
            )

        log_entry = {
            "timestamp": (
                pending["timestamp"]
                if pending is not None
                else utc_now_iso()
            ),
            "request_id": request_id,
            "user_id": user_id,
            "input": pending["input"] if pending is not None else "",
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "latency_ms": latency_ms,
        }

        self.logs.append(log_entry)
        return log_entry
    
    def export_json(self, filepath: str | None = None):
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)

        path.write_text(
            json.dumps(
                self.logs,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        return str(path)

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
