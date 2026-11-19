"""PEG parser for the TDG text projection, and the canonical printer.

Whitespace and /* */ comments are insignificant; every declaration and field
is terminated explicitly, so the text has no notion of lines or indentation.
"""

from __future__ import annotations

import json

from parsimonious.exceptions import ParseError
from parsimonious.grammar import Grammar
from parsimonious.nodes import Node

from .core import Capability, Policy, Predicate, Program, Span, Stage, TdgError

GRAMMAR = Grammar(r"""
    program     = _ decl*
    decl        = (cap / stage) _
    cap         = "cap" __ capkind __ ident _ "{" _ capfield* "}"
    capkind     = "net" / "fs" / "model" / "shell" / "custom"
    capfield    = (allow_f / root_f / mode_f / id_f / tokens_f / config_f) _ ";" _
    allow_f     = "allow" (_ string)+
    root_f      = "root" _ string
    mode_f      = "mode" __ fsmode
    fsmode      = "rw" / "read" / "write"
    id_f        = "id" _ string
    tokens_f    = "tokens" __ int
    config_f    = "config" _ string

    stage       = "stage" __ ident _ ":" _ kind opname? _ "{" _ sfield* "}"
    kind        = "entry" / "tool" / "transform" / "branch" / "output"
    opname      = __ dotted
    dotted      = ident ("." ident)?
    sfield      = (after_f / in_f / out_f / uses_f / arg_f / check_f / fail_f / viol_f / rand_f / when_f) _ ";" _
    after_f     = "after" __ idlist
    in_f        = "in" __ idlist
    out_f       = "out" __ ident
    uses_f      = "uses" __ idlist
    arg_f       = "arg" __ kv (_ "," _ kv)*
    kv          = ident _ "=" _ value
    check_f     = "check" __ pred
    pred        = status_p / maxbytes_p / nonempty_p / max_p / min_p
    status_p    = "status" __ int (".." int)?
    maxbytes_p  = "maxbytes" __ int
    nonempty_p  = "nonempty"
    max_p       = "max" __ number
    min_p       = "min" __ number
    fail_f      = "fail" __ policy
    viol_f      = "viol" __ policy
    policy      = retry_p / "abort" / "propose"
    retry_p     = "retry" __ int
    rand_f      = "rand"
    when_f      = "when" __ ident

    idlist      = ident (_ "," _ ident)*
    value       = string / number / bool
    bool        = "true" / "false"
    number      = ~r"-?[0-9]+(\.[0-9]+)?"
    int         = ~r"[0-9]+"
    string      = ~r'"(?:[^"\\]|\\.)*"'
    ident       = ~r"[A-Za-z_][A-Za-z0-9_]*"
    _           = (ws / comment)*
    __          = (ws / comment)+
    ws          = ~r"\s+"
    comment     = ~r"/\*.*?\*/"s
""")


def _find(node: Node, name: str) -> list[Node]:
    """Named descendants of `node`, without descending into matches."""
    out, stack = [], list(reversed(node.children))
    while stack:
        n = stack.pop()
        if n.expr_name == name:
            out.append(n)
        else:
            stack.extend(reversed(n.children))
    return out


def _first(node: Node, name: str) -> Node | None:
    found = _find(node, name)
    return found[0] if found else None


def _value(node: Node):
    inner = node.children[0]
    if inner.expr_name == "string":
        return json.loads(inner.text)
    if inner.expr_name == "bool":
        return inner.text == "true"
    t = inner.text
    return float(t) if "." in t else int(t)


def _idents(node: Node) -> tuple[str, ...]:
    return tuple(n.text for n in _find(node, "ident"))


def _policy(node: Node) -> Policy:
    p = _first(node, "policy")
    r = _first(p, "retry_p")
    if r is not None:
        return Policy("retry", int(_first(r, "int").text))
    return Policy(p.text)


def _pred(node: Node) -> Predicate:
    p = _first(node, "pred").children[0]
    if p.expr_name == "status_p":
        ints = [int(n.text) for n in _find(p, "int")]
        return Predicate("status", (ints[0], ints[-1]))
    if p.expr_name == "maxbytes_p":
        return Predicate("maxbytes", (int(_first(p, "int").text),))
    if p.expr_name == "nonempty_p":
        return Predicate("nonempty", ())
    num = _first(p, "number").text
    return Predicate(p.expr_name[:-2], (float(num) if "." in num else int(num),))


def _cap(node: Node) -> Capability:
    kw: dict = {"allow": ()}
    for f in _find(node, "capfield"):
        inner = f.children[0].children[0]
        name = inner.expr_name
        if name == "allow_f":
            kw["allow"] = kw["allow"] + tuple(json.loads(s.text) for s in _find(inner, "string"))
        elif name == "root_f":
            kw["root"] = json.loads(_first(inner, "string").text)
        elif name == "mode_f":
            kw["mode"] = _first(inner, "fsmode").text
        elif name == "id_f":
            kw["model_id"] = json.loads(_first(inner, "string").text)
        elif name == "tokens_f":
            kw["max_tokens"] = int(_first(inner, "int").text)
        elif name == "config_f":
            kw["config"] = json.loads(_first(inner, "string").text)
    return Capability(
        name=_first(node, "ident").text, kind=_first(node, "capkind").text,
        span=Span(node.start, node.end), **kw,
    )


def _stage(node: Node) -> Stage:
    kw: dict = {}
    args: list = []
    checks: list = []
    for f in _find(node, "sfield"):
        inner = f.children[0].children[0]
        name = inner.expr_name
        if name == "after_f":
            kw["after"] = kw.get("after", ()) + _idents(inner)
        elif name == "in_f":
            kw["inputs"] = kw.get("inputs", ()) + _idents(inner)
        elif name == "out_f":
            kw["out"] = _first(inner, "ident").text
        elif name == "uses_f":
            kw["uses"] = kw.get("uses", ()) + _idents(inner)
        elif name == "arg_f":
            for kv in _find(inner, "kv"):
                args.append((_first(kv, "ident").text, _value(_first(kv, "value"))))
        elif name == "check_f":
            checks.append(_pred(inner))
        elif name == "fail_f":
            kw["on_fail"] = _policy(inner)
        elif name == "viol_f":
            kw["on_violation"] = _policy(inner)
        elif name == "rand_f":
            kw["stochastic"] = True
        elif name == "when_f":
            kw["when"] = _first(inner, "ident").text
    op = _first(node, "opname")
    return Stage(
        name=_first(node, "ident").text, kind=_first(node, "kind").text,
        op=_first(op, "dotted").text if op is not None else None,
        args=tuple(args), checks=tuple(checks), span=Span(node.start, node.end), **kw,
    )


def parse(text: str) -> Program:
    try:
        tree = GRAMMAR.parse(text)
    except ParseError as e:
        raise TdgError(f"parse error at offset {e.pos}: {text[e.pos:e.pos + 30]!r}") from None
    caps, stages = [], []
    for decl in _find(tree, "decl"):
        inner = decl.children[0].children[0]
        (caps if inner.expr_name == "cap" else stages).append(
            _cap(inner) if inner.expr_name == "cap" else _stage(inner)
        )
    return Program(tuple(caps), tuple(stages))


def _lit(v) -> str:
    return json.dumps(v) if isinstance(v, (str, bool)) else repr(v)


def to_text(p: Program) -> str:
    """Deterministic text projection of a program (inverse of `parse`)."""
    parts = []
    for c in p.caps:
        f = []
        if c.allow:
            f.append("allow " + " ".join(json.dumps(a) for a in c.allow) + ";")
        if c.root is not None:
            f.append(f"root {json.dumps(c.root)};")
        if c.mode is not None:
            f.append(f"mode {c.mode};")
        if c.model_id is not None:
            f.append(f"id {json.dumps(c.model_id)};")
        if c.max_tokens is not None:
            f.append(f"tokens {c.max_tokens};")
        if c.config is not None:
            f.append(f"config {json.dumps(c.config)};")
        parts.append(f"cap {c.kind} {c.name}{{{''.join(f)}}}")
    for s in p.stages:
        f = []
        if s.after:
            f.append(f"after {','.join(s.after)};")
        if s.inputs:
            f.append(f"in {','.join(s.inputs)};")
        if s.out:
            f.append(f"out {s.out};")
        if s.uses:
            f.append(f"uses {','.join(s.uses)};")
        if s.args:
            f.append("arg " + ",".join(f"{k}={_lit(v)}" for k, v in s.args) + ";")
        f.extend(f"check {c.text()};" for c in s.checks)
        if s.on_fail != Policy():
            f.append(f"fail {s.on_fail.text()};")
        if s.on_violation != Policy():
            f.append(f"viol {s.on_violation.text()};")
        if s.stochastic:
            f.append("rand;")
        if s.when:
            f.append(f"when {s.when};")
        head = f"stage {s.name}:{s.kind}" + (f" {s.op}" if s.op else "")
        parts.append(f"{head}{{{''.join(f)}}}")
    return "\n".join(parts) + "\n"
