// Default policy rules — the firewall's signatures for agent actions.
// Mirror of voanfw/rules.py. First matching rule wins (see policy.ts). Category
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
    pattern: /rm\s+-rf|mkfs|dd\s+if=|>\s*\/dev\/sd|:\(\)\s*\{|format\s+[a-z]:|del\s+\/[sfq]|shutdown|reboot/i,
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
