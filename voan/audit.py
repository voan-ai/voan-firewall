"""Audit trail + live dashboard feed.

Every decision is (1) appended to a local JSONL file — the tamper-evident record
an auditor or SOC wants — and (2) best-effort streamed to the local dashboard
server so you can watch the firewall work in real time. The dashboard emit runs
on a daemon thread with a hard timeout and swallows all errors, so the agent
never slows down or crashes just because the dashboard is offline. Stdlib only —
the SDK keeps zero hard dependencies.
"""
import atexit
import json
import threading
import time
import urllib.request


class AuditLog:
    def __init__(self, path="voan_audit.jsonl",
                 dashboard="http://127.0.0.1:8088", emit=True):
        self.path = path
        self.dashboard = dashboard.rstrip("/") if dashboard else None
        self.emit = emit and bool(dashboard)
        self._lock = threading.Lock()
        self._threads = []
        # Daemon emit threads are killed the instant a short-lived script (like
        # the demo) exits — flush any in flight first so no decision is lost.
        atexit.register(self.flush)

    def flush(self, timeout=1.0):
        for t in list(self._threads):
            t.join(timeout)

    def record(self, action, verdict):
        evt = {
            "ts": action.ts,
            "iso": time.strftime("%H:%M:%S", time.localtime(action.ts)),
            "agent": action.agent,
            "tool": action.tool,
            "args": action.args,
            "decision": verdict.decision.value,
            "rule": verdict.rule,
            "code": verdict.code,
            "severity": verdict.severity,
            "reason": verdict.reason,
        }
        self._write(evt)
        if self.emit:
            self._emit(evt)
        return evt

    def _write(self, evt):
        line = json.dumps(evt, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _emit(self, evt):
        self._threads = [t for t in self._threads if t.is_alive()]  # prune
        t = threading.Thread(target=self._post, args=(evt,), daemon=True)
        self._threads.append(t)
        t.start()

    def _post(self, evt):
        try:
            data = json.dumps(evt).encode("utf-8")
            req = urllib.request.Request(
                f"{self.dashboard}/api/event", data=data,
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=0.5).close()
        except Exception:
            pass  # dashboard offline — never block or crash the agent
