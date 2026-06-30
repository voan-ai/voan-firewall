// The policy engine — the firewall's brain (mirror of voan/policy.py).
// First matching rule wins; nothing matches => default-allow. Flip `default` to
// "block" for a deny-by-default posture.
import type { Action, DecisionType, Verdict } from "./schema.ts";
import { DEFAULT_RULES, ruleMatches, type Rule } from "./rules.ts";

export class PolicyEngine {
  rules: Rule[];
  default: DecisionType;

  constructor(rules?: Rule[], def: DecisionType = "allow") {
    this.rules = rules ? [...rules] : [...DEFAULT_RULES];
    this.default = def;
  }

  addRule(rule: Rule, front = true): this {
    if (front) this.rules.unshift(rule);
    else this.rules.push(rule);
    return this;
  }

  evaluate(action: Action): Verdict {
    for (const rule of this.rules) {
      if (ruleMatches(rule, action)) {
        return {
          decision: rule.decision, rule: rule.id, code: rule.code,
          severity: rule.severity, reason: rule.reason,
        };
      }
    }
    return {
      decision: this.default, rule: "default", code: "",
      severity: "Low", reason: "no rule matched",
    };
  }
}
