"""Typed AST and graph types shared by the parser, compiler and runtime."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

STAGE_KINDS = ("entry", "tool", "transform", "branch", "output")
CAP_KINDS = ("net", "fs", "model", "shell", "custom")
FS_MODES = ("read", "write", "rw")
POLICY_ACTIONS = ("retry", "abort", "propose")
PREDICATE_OPS = ("status", "maxbytes", "nonempty", "max", "min")

# tool name -> (capability kind it needs, output type)
TOOLS = {
    "net.get": ("net", "response"),
    "fs.read": ("fs", "text"),
    "fs.write": ("fs", "int"),
    "shell.run": ("shell", "text"),
    "model.call": ("model", "text"),
    "custom.call": ("custom", "any"),
}

# transform/branch name -> output type
TRANSFORMS = {
    "identity": "any",
    "body": "text",
    "status": "int",
    "parse_json": "json",
    "field": "any",
    "count": "int",
    "length": "int",
    "sum": "number",
    "upper": "text",
    "concat": "text",
    "template": "text",
    "merge": "json",
}
BRANCHES = {"gt": "bool", "lt": "bool", "eq": "bool", "truthy": "bool"}

# predicate op -> output types it may be applied to ("any" always allowed)
PREDICATE_TYPES = {
    "status": {"response"},
    "maxbytes": {"text", "response", "json"},
    "nonempty": {"text", "json", "response"},
    "max": {"int", "number"},
    "min": {"int", "number"},
}


class TdgError(Exception):
    pass


@dataclass(frozen=True)
class Span:
    start: int
    end: int


@dataclass(frozen=True)
class Capability:
    name: str
    kind: str
    allow: tuple[str, ...] = ()
    root: str | None = None
    mode: str | None = None
    model_id: str | None = None
    max_tokens: int | None = None
    config: str | None = None
    span: Span | None = field(default=None, compare=False)


@dataclass(frozen=True)
class Predicate:
    op: str
    args: tuple[Any, ...] = ()

    def text(self) -> str:
        if self.op == "status":
            lo, hi = self.args
            return f"status {lo}" if lo == hi else f"status {lo}..{hi}"
        if self.op == "nonempty":
            return "nonempty"
        return f"{self.op} {self.args[0]}"


@dataclass(frozen=True)
class Policy:
    action: str = "abort"
    count: int = 0

    def text(self) -> str:
        return f"retry {self.count}" if self.action == "retry" else self.action


@dataclass(frozen=True)
class Stage:
    name: str
    kind: str
    op: str | None = None
    after: tuple[str, ...] = ()
    inputs: tuple[str, ...] = ()
    out: str | None = None
    uses: tuple[str, ...] = ()
    args: tuple[tuple[str, Any], ...] = ()
    checks: tuple[Predicate, ...] = ()
    on_fail: Policy = Policy()
    on_violation: Policy = Policy()
    stochastic: bool = False
    when: str | None = None
    span: Span | None = field(default=None, compare=False)

    @property
    def output_name(self) -> str:
        return self.out or self.name

    def arg(self, key: str, default: Any = None) -> Any:
        for k, v in self.args:
            if k == key:
                return v
        return default


@dataclass(frozen=True)
class Program:
    caps: tuple[Capability, ...]
    stages: tuple[Stage, ...]

    def stage(self, name: str) -> Stage:
        for s in self.stages:
            if s.name == name:
                return s
        raise KeyError(name)

    def cap(self, name: str) -> Capability:
        for c in self.caps:
            if c.name == name:
                return c
        raise KeyError(name)


# ---------------------------------------------------------------- dict form
# The dict form is what the binary emitter serializes and what repair patches
# (RFC 6902 JSON Patch) are expressed against.

def program_to_dict(p: Program) -> dict:
    def cap(c: Capability) -> dict:
        d = {"name": c.name, "kind": c.kind}
        for k in ("root", "mode", "model_id", "max_tokens", "config"):
            if getattr(c, k) is not None:
                d[k] = getattr(c, k)
        if c.allow:
            d["allow"] = list(c.allow)
        return d

    def stage(s: Stage) -> dict:
        d: dict[str, Any] = {"name": s.name, "kind": s.kind}
        if s.op:
            d["op"] = s.op
        for k in ("after", "inputs", "uses"):
            if getattr(s, k):
                d[k] = list(getattr(s, k))
        if s.out:
            d["out"] = s.out
        if s.args:
            d["args"] = {k: v for k, v in s.args}
        if s.checks:
            d["checks"] = [{"op": c.op, "args": list(c.args)} for c in s.checks]
        if s.on_fail != Policy():
            d["on_fail"] = asdict(s.on_fail)
        if s.on_violation != Policy():
            d["on_violation"] = asdict(s.on_violation)
        if s.stochastic:
            d["stochastic"] = True
        if s.when:
            d["when"] = s.when
        return d

    return {"caps": [cap(c) for c in p.caps], "stages": [stage(s) for s in p.stages]}


def program_from_dict(d: dict) -> Program:
    caps = tuple(
        Capability(
            name=c["name"], kind=c["kind"], allow=tuple(c.get("allow", ())),
            root=c.get("root"), mode=c.get("mode"), model_id=c.get("model_id"),
            max_tokens=c.get("max_tokens"), config=c.get("config"),
        )
        for c in d.get("caps", ())
    )
    stages = tuple(
        Stage(
            name=s["name"], kind=s["kind"], op=s.get("op"),
            after=tuple(s.get("after", ())), inputs=tuple(s.get("inputs", ())),
            out=s.get("out"), uses=tuple(s.get("uses", ())),
            args=tuple(s.get("args", {}).items()),
            checks=tuple(Predicate(c["op"], tuple(c.get("args", ()))) for c in s.get("checks", ())),
            on_fail=Policy(**s["on_fail"]) if "on_fail" in s else Policy(),
            on_violation=Policy(**s["on_violation"]) if "on_violation" in s else Policy(),
            stochastic=s.get("stochastic", False), when=s.get("when"),
        )
        for s in d.get("stages", ())
    )
    return Program(caps, stages)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()
