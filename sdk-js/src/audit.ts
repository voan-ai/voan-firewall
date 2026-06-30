// Audit trail + live dashboard feed (mirror of voanfw/audit.py).
// Every decision is appended to a JSONL file and best-effort streamed to the
// local dashboard. The POST is fire-and-forget with a hard timeout so the agent
// never slows down; call `flush()` before a short script exits so in-flight
// posts complete (Node would otherwise exit and drop them).
import { appendFileSync } from "node:fs";
import type { Action, Verdict } from "./schema.ts";

export interface AuditEvent {
  ts: number; iso: string; agent: string; tool: string;
  args: Record<string, unknown>; decision: string; rule: string;
  code: string; severity: string; reason: string;
}

export class AuditLog {
  path: string;
  dashboard: string | null;
  emit: boolean;
  private pending: Promise<void>[] = [];

  constructor(
    path = "voan_audit.jsonl",
    dashboard: string | null = "http://127.0.0.1:8088",
    emit = true,
  ) {
    this.path = path;
    this.dashboard = dashboard ? dashboard.replace(/\/+$/, "") : null;
    this.emit = emit && !!dashboard;
  }

  record(action: Action, verdict: Verdict): AuditEvent {
    const evt: AuditEvent = {
      ts: action.ts,
      iso: new Date(action.ts * 1000).toTimeString().slice(0, 8),
      agent: action.agent, tool: action.tool, args: action.args,
      decision: verdict.decision, rule: verdict.rule, code: verdict.code,
      severity: verdict.severity, reason: verdict.reason,
    };
    try {
      appendFileSync(this.path, JSON.stringify(evt) + "\n");
    } catch {
      /* never let logging crash the agent */
    }
    if (this.emit) this.pending.push(this.post(evt));
    return evt;
  }

  private async post(evt: AuditEvent): Promise<void> {
    try {
      await fetch(`${this.dashboard}/api/event`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(evt),
        signal: AbortSignal.timeout(500),
      });
    } catch {
      /* dashboard offline — ignore */
    }
  }

  async flush(): Promise<void> {
    await Promise.allSettled(this.pending);
    this.pending = [];
  }
}
