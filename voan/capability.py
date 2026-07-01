"""Capability engine — per-value provenance, the CaMeL / FIDES core.

The tiers elsewhere in Voan approximate provenance with string matching. This is
the real thing: every value carries a CAPABILITY — an integrity label (was it
derived only from trusted input, or did untrusted data touch it?) and a
confidentiality label (which sink classes may receive it). Capabilities PROPAGATE
through operations: combine a trusted and an untrusted value and the result is
untrusted; combine two values and the readers are the intersection. Two invariants
are then enforced deterministically, per value, and cannot be prompted away:

  INTEGRITY (anti-hijack): an UNTRUSTED value may not be a control-sensitive
    argument of a side effect (a recipient, destination, or command). If the payee
    of a transfer was derived from an email, an injection controlled it — deny.
  CONFIDENTIALITY (anti-exfil): a value may only reach a sink whose class is in its
    readers set. A CONFIDENTIAL value routed to an EXTERNAL sink is denied.

This is the provable property CaMeL gets from a capability interpreter. Agents that
thread Capsules through their tool calls get that guarantee for those values; the
`Firewall(taint=/flow=)` tiers are the automatic, approximate version for agents
that don't. (CaMeL: Debenedetti et al. 2025; FIDES: Microsoft 2025.)
"""
TRUSTED, UNTRUSTED = "trusted", "untrusted"
ANY = "*"   # readers = {ANY} means "may flow anywhere"

# argument names that steer WHERE/HOW a side effect acts — untrusted data here is
# a hijack, so these are the control-sensitive sinks for the integrity invariant.
SENSITIVE_PARAMS = ("recipient", "receiver", "payee", "to", "dest", "destination",
                    "address", "account", "iban", "url", "command", "cmd", "path",
                    "channel", "user", "query")


class Denied(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class Capsule:
    """A value tagged with a capability (integrity + confidentiality readers)."""
    __slots__ = ("value", "integrity", "readers", "source")

    def __init__(self, value, integrity=TRUSTED, readers=frozenset({ANY}), source=None):
        self.value = value
        self.integrity = integrity
        self.readers = frozenset(readers)
        self.source = source

    def derive(self, new_value, source=None):
        """A value extracted or computed FROM this one inherits its capability."""
        return Capsule(new_value, self.integrity, self.readers, source or self.source)

    @staticmethod
    def combine(new_value, *capsules, source=None):
        """Capability of a value computed from several: untrusted if ANY input is,
        readers = intersection (only sinks all inputs permit)."""
        caps = [c for c in capsules if isinstance(c, Capsule)]
        if not caps:
            return Capsule(new_value, TRUSTED, frozenset({ANY}), source)
        integrity = TRUSTED if all(c.integrity == TRUSTED for c in caps) else UNTRUSTED
        readers = caps[0].readers
        for c in caps[1:]:
            readers = _intersect(readers, c.readers)
        return Capsule(new_value, integrity, readers, source)

    def __repr__(self):
        return f"Capsule({self.value!r}, {self.integrity}, readers={set(self.readers)})"


def _intersect(a, b):
    if ANY in a:
        return b
    if ANY in b:
        return a
    return a & b


class CapabilityEngine:
    """Enforces the integrity + confidentiality invariants on tool calls whose
    arguments are Capsules. `sink_class` maps a tool to its sink class (e.g.
    'external'); `readers_for` gives the confidentiality of a source tool's output."""

    def __init__(self, sink_class=None, sensitive_params=SENSITIVE_PARAMS):
        self.sink_class = dict(sink_class or {})
        self.sensitive = tuple(sensitive_params)

    def trusted(self, value):
        return Capsule(value, TRUSTED, frozenset({ANY}), "user")

    def source(self, tool, untrusted=True, readers=frozenset({ANY})):
        """A capsule for data returned by `tool`. Tool outputs are UNTRUSTED by
        default (that is where injections live); pass readers to mark it
        confidential (e.g. readers={'internal'} means 'internal sinks only')."""
        integ = UNTRUSTED if untrusted else TRUSTED
        return Capsule(None, integ, readers, tool)

    def _is_sensitive(self, key):
        return any(s in str(key).lower() for s in self.sensitive)

    def check_call(self, tool, args):
        """Raise Denied if any Capsule argument violates an invariant, else return
        True. Non-Capsule args are treated as trusted literals (the caller vouches)."""
        cls = self.sink_class.get(tool)
        for k, v in (args or {}).items():
            if not isinstance(v, Capsule):
                continue
            if v.integrity == UNTRUSTED and self._is_sensitive(k):
                raise Denied(f"untrusted value steers '{k}' of {tool} "
                             f"(provenance: {v.source}) — hijack")
            if cls is not None and ANY not in v.readers and cls not in v.readers:
                raise Denied(f"confidential value (readers={set(v.readers)}) may not "
                             f"reach '{cls}' sink {tool} — exfiltration")
        return True

    def _tag_output(self, tool, args, result, source, readers):
        """Capability of a tool's OUTPUT: untrusted if this tool is an untrusted
        source OR any input was untrusted (taint propagates through the call);
        readers = intersection of the inputs' readers and this tool's own."""
        in_caps = [v for v in args.values() if isinstance(v, Capsule)]
        combined = Capsule.combine(result, *in_caps, source=tool)
        integ = UNTRUSTED if (source or combined.integrity == UNTRUSTED) else TRUSTED
        rd = combined.readers if readers == frozenset({ANY}) else _intersect(combined.readers, readers)
        return Capsule(result, integ, rd, tool)

    def guard(self, fn, tool, untrusted=True, readers=frozenset({ANY})):
        """Wrap a tool so (1) its Capsule arguments are checked against both
        invariants before it runs, and (2) its RESULT is returned as a Capsule whose
        label propagates this tool's provenance AND its untrusted inputs — so taint
        flows into whatever the agent does next."""
        def wrapped(**kwargs):
            self.check_call(tool, kwargs)
            raw = {k: (v.value if isinstance(v, Capsule) else v) for k, v in kwargs.items()}
            return self._tag_output(tool, kwargs, fn(**raw), untrusted, readers)
        wrapped.__name__ = getattr(fn, "__name__", tool)
        return wrapped

    def guard_tools(self, tools, sources=None, confidential=None):
        """Guard a dict {name: fn}. `sources` names tools whose output is untrusted
        (default: all — tool output is the injection surface). `confidential` maps a
        tool -> its readers set (its output may only reach those sink classes)."""
        sources = set(tools if sources is None else sources)
        confidential = confidential or {}
        return {n: self.guard(f, n, untrusted=(n in sources),
                              readers=confidential.get(n, frozenset({ANY})))
                for n, f in tools.items()}

    def run(self, program, tools, sources=None, confidential=None, env=None):
        """Interpret a capability-tracked PROGRAM — the CaMeL execution model. This
        removes the last gap of the wrapped-tool version: the agent emits a plan of
        steps and Voan runs it, threading capabilities AUTOMATICALLY so no untrusted
        value can escape into a sensitive sink.

        Each step is {tool, args, var?}. An arg value of "$name" resolves to the
        capsule a prior step stored in `name` (so data read from a tool carries its
        untrusted/confidential label into later steps); any other value is a trusted
        literal. `sources` = tools whose own output is untrusted (default: all);
        `confidential` = {tool: readers}. Raises Denied on the first violation.
        Returns the env mapping var -> Capsule."""
        env = dict(env or {})
        srcs = set(tools if sources is None else sources)
        conf = confidential or {}
        for step in program:
            tool = step["tool"]
            args = {k: self._resolve(v, env) for k, v in step.get("args", {}).items()}
            self.check_call(tool, args)
            raw = {k: (v.value if isinstance(v, Capsule) else v) for k, v in args.items()}
            out = self._tag_output(tool, args, tools[tool](**raw),
                                   tool in srcs, conf.get(tool, frozenset({ANY})))
            if step.get("var"):
                env[step["var"]] = out
        return env

    @staticmethod
    def _resolve(value, env):
        if isinstance(value, str) and value.startswith("$"):
            base, _, field = value[1:].partition(".")   # supports $var and $var.field
            cap = env.get(base)
            if cap is None:
                return value
            if field and isinstance(cap, Capsule) and isinstance(cap.value, dict):
                return cap.derive(cap.value.get(field, ""))   # field inherits the taint
            return cap
        return value                               # trusted literal
