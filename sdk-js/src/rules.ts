// Default policy rules — the firewall's signatures for agent actions.
// Mirror of voan/rules.py. First matching rule wins (see policy.ts). Category
// codes match the Voan scanner taxonomy: RCE / DEL / AEX / CRH / AGT.
import type { Action, DecisionType } from "./schema.ts";
import { Decision } from "./schema.ts";

export interface Rule {
  id: string;
  decision: DecisionType;
  code: string;
  severity: string;
  reason: string;
  tools?: string[]; // omitted/empty = match any tool
  pattern?: RegExp; // omitted = match any args
}

export function ruleMatches(rule: Rule, action: Action): boolean {
  if (rule.tools && rule.tools.length && !rule.tools.includes(action.tool)) {
    return false;
  }
  if (rule.pattern) {
    return rule.pattern.test(JSON.stringify(action.args));
  }
  return true;
}

const SHELL = ["run_command", "shell", "exec", "bash", "sh", "system", "terminal"];
const DB = ["delete_database", "drop_table", "execute_sql", "run_query", "db"];
const MAIL = ["send_email", "email", "send_message", "send_mail", "notify"];
const HTTP = ["http_request", "fetch", "request", "post", "webhook", "curl"];
const PAY = ["process_refund", "send_payment", "transfer", "charge", "payout"];

const EXFIL = /attacker|evil\.test|exfil@|refunds@attacker|\.onion\b/i;

export const DEFAULT_RULES: Rule[] = [
  {
    id: "SHELL_DESTRUCTIVE", decision: Decision.BLOCK, code: "RCE",
    severity: "Critical", reason: "Destructive or self-propagating shell command",
    tools: SHELL,
    // rm recursive+force in any flag order, plus find -delete, dd of=/dev/, mkfs,
    // shred, wipefs, redirect-to-device, chmod 000, truncate, fork bomb, PowerShell
    // Remove-Item -Recurse -Force (mirrors voan/rules.py).
    pattern: /\brm\b[^|;&\n]*(?:-r[a-z]*f|-f[a-z]*r|-r\s+-f|-f\s+-r|--recursive|--force)|\bfind\b[^|;&\n]*-delete|\bfind\b[^|;&\n]*-exec\s+rm|\bdd\b[^|;&\n]*of=\/dev\/|\bmkfs|\bshred\b|\bwipefs\b|>\s*\/dev\/(?:sd|nvme|hd|disk|mapper)|\bmv\b[^|;&\n]*\s\/dev\/null|\bchmod\b[^|;&\n]*\b000\b|\btruncate\b[^|;&\n]*-s\s*0\b|:\(\)\s*\{|\bshutdown\b|\breboot\b|del\s+\/[sfq]|format\s+[a-z]:|remove-item\b[^|;&\n]*-recurse[^|;&\n]*-force|remove-item\b[^|;&\n]*-force[^|;&\n]*-recurse/i,
  },
  {
    id: "SHELL_PIPE_EXEC", decision: Decision.BLOCK, code: "RCE",
    severity: "Critical", reason: "Pipe-to-shell remote payload execution",
    tools: SHELL,
    pattern: /curl[^|]*\|\s*(sh|bash)|wget[^|]*\|\s*(sh|bash)|iex\s*\(|invoke-expression/i,
  },
  {
    id: "DB_DESTRUCTIVE", decision: Decision.BLOCK, code: "DEL",
    severity: "Critical", reason: "Destructive database operation",
    tools: DB,
    pattern: /drop\s+(table|database)|truncate\s+|delete\s+from(?!.*where)/i,
  },
  {
    id: "EXFIL_CHANNEL", decision: Decision.BLOCK, code: "AEX",
    severity: "High", reason: "Data sent to an attacker-controlled destination",
    tools: [...MAIL, ...HTTP], pattern: EXFIL,
  },
  {
    id: "CREDENTIAL_LEAK", decision: Decision.BLOCK, code: "CRH",
    severity: "High", reason: "Secret or credential about to leave the agent",
    tools: [...MAIL, ...HTTP],
    pattern: /AGENT_TOKEN|api[_-]?key|secret|password|BEGIN [A-Z ]*PRIVATE/i,
  },
  {
    id: "PAYMENT_HUMAN", decision: Decision.ASK, code: "AGT",
    severity: "High", reason: "Money movement requires human approval", tools: PAY,
  },
  {
    id: "EXTERNAL_SEND", decision: Decision.ASK, code: "AGT",
    severity: "Medium", reason: "Outbound message to an external recipient",
    tools: [...MAIL, ...HTTP],
  },
];

// --- Egress allowlist (mirror of voan/rules.py) -----------------------------
const DOMAIN_RX = /(?:[a-z0-9-]+\.)+[a-z]{2,}/gi;
const IP_RX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DEST_KEYS = ["dest", "url", "uri", "to", "endpoint", "host", "target",
  "recipient", "webhook", "callback", "address", "server"];

function hostOf(v: unknown): string {
  let s = String(v).trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  s = s.split("/")[0].split("?")[0].split("@").pop() ?? "";
  if (s.startsWith("[")) return s.slice(1).split("]")[0];
  return s.split(":")[0];
}

function allowedHost(h: string, allowed: string[]): boolean {
  h = h.replace(/\.+$/, "");
  return !!h && allowed.some((a) => h === a || h.endsWith("." + a));
}

function pairs(obj: unknown, key = ""): Array<[string, unknown]> {
  if (Array.isArray(obj)) return obj.flatMap((v) => pairs(v, key));
  if (obj && typeof obj === "object")
    return Object.entries(obj).flatMap(([k, v]) => pairs(v, k));
  return [[key, obj]];
}

/** First destination (domain or raw IP) in `args` not covered by `allowlist`, or
 *  null. Destination-named fields are fail-closed (defeats encoded-IP evasions). */
export function egressViolation(
  args: Record<string, unknown>, allowlist: string[],
): string | null {
  const allowed = allowlist.map((a) => a.toLowerCase().replace(/^\.+/, ""));
  for (const [k, v] of pairs(args)) {
    if (DEST_KEYS.some((dk) => k.toLowerCase().includes(dk))) {
      const h = hostOf(v);
      if (h && !allowedHost(h, allowed)) return h;
    }
  }
  const blob = JSON.stringify(args).toLowerCase();
  for (const d of blob.match(DOMAIN_RX) ?? []) {
    const dd = (d.split("@").pop() ?? "").replace(/\.+$/, "");
    if (!allowedHost(dd, allowed)) return dd;
  }
  for (const ip of blob.match(IP_RX) ?? []) {
    if (!allowed.includes(ip)) return ip;
  }
  return null;
}
