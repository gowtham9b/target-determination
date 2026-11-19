"""Validation, optimization and binary emission.

compile_program() turns a parsed Program into a validated IR, or raises
CompileError carrying every diagnostic found.
"""

from __future__ import annotations

import hashlib
import posixpath
from dataclasses import dataclass, field

import msgpack

from .core import (
    BRANCHES, CAP_KINDS, FS_MODES, PREDICATE_TYPES, STAGE_KINDS, TOOLS, TRANSFORMS,
    Program, Stage, TdgError, program_from_dict, program_to_dict,
)

MAGIC = b"TDG"
FORMAT_VERSION = 1


@dataclass(frozen=True)
class Diagnostic:
    code: str
    message: str
    stage: str | None = None
    field: str | None = None
    index: int | None = None
    value: str | None = None


class CompileError(TdgError):
    def __init__(self, diagnostics: list[Diagnostic]):
        self.diagnostics = diagnostics
        super().__init__("; ".join(f"{d.code}: {d.message}" for d in diagnostics))


@dataclass
class IR:
    program: Program
    levels: list[list[str]]
    cap_index: dict[str, int]
    targets: list[str]
    pruned: list[str] = field(default_factory=list)
    warnings: list[Diagnostic] = field(default_factory=list)


def output_type(s: Stage) -> str:
    if s.kind == "tool":
        return TOOLS[s.op][1]
    if s.kind == "transform":
        return TRANSFORMS[s.op]
    if s.kind == "branch":
        return BRANCHES[s.op]
    return "any"


def validate(p: Program) -> list[Diagnostic]:
    diags: list[Diagnostic] = []
    names = [s.name for s in p.stages]
    by_name = {s.name: s for s in p.stages}
    caps = {c.name: c for c in p.caps}

    for n in {n for n in names if names.count(n) > 1}:
        diags.append(Diagnostic("DUP_STAGE", f"stage {n!r} declared more than once", n))
    for c in p.caps:
        if c.kind not in CAP_KINDS:
            diags.append(Diagnostic("BAD_CAP", f"unknown capability kind {c.kind!r}"))
        if c.kind == "fs" and (c.root is None or c.mode not in FS_MODES):
            diags.append(Diagnostic("BAD_CAP", f"fs capability {c.name!r} needs root and mode"))
        if c.kind in ("net", "shell") and not c.allow:
            diags.append(Diagnostic("BAD_CAP", f"{c.kind} capability {c.name!r} has an empty allow list"))
        if c.kind == "model" and (c.model_id is None or c.max_tokens is None):
            diags.append(Diagnostic("BAD_CAP", f"model capability {c.name!r} needs id and tokens"))

    for s in p.stages:
        if s.kind not in STAGE_KINDS:
            diags.append(Diagnostic("BAD_KIND", f"unknown stage kind {s.kind!r}", s.name))
            continue
        table = {"tool": TOOLS, "transform": TRANSFORMS, "branch": BRANCHES}.get(s.kind)
        if table is not None and s.op not in table:
            diags.append(Diagnostic("UNKNOWN_OP", f"unknown {s.kind} {s.op!r}", s.name, "op", None, s.op))
        for i, d in enumerate(s.after):
            if d == s.name:
                diags.append(Diagnostic("SELF_DEP", f"{s.name!r} depends on itself", s.name, "after", i, d))
            elif d not in by_name:
                diags.append(Diagnostic("UNKNOWN_DEP", f"{s.name!r} depends on undefined stage {d!r}", s.name, "after", i, d))
        dep_outputs = {by_name[d].output_name for d in s.after if d in by_name}
        for i, x in enumerate(s.inputs):
            if x not in dep_outputs:
                diags.append(Diagnostic("UNKNOWN_INPUT", f"{s.name!r} reads {x!r}, which no dependency produces", s.name, "inputs", i, x))
        if s.when is not None:
            w = by_name.get(s.when)
            if w is None or w.kind != "branch" or s.when not in s.after:
                diags.append(Diagnostic("BAD_WHEN", f"{s.name!r} is guarded by {s.when!r}, which must be a branch it depends on", s.name, "when", None, s.when))
        for i, u in enumerate(s.uses):
            if u not in caps:
                diags.append(Diagnostic("UNKNOWN_CAP", f"{s.name!r} uses undefined capability {u!r}", s.name, "uses", i, u))
        if s.kind == "tool" and s.op in TOOLS:
            need = TOOLS[s.op][0]
            if not any(caps[u].kind == need for u in s.uses if u in caps):
                diags.append(Diagnostic("NO_CAP", f"tool stage {s.name!r} calls {s.op} without a {need} capability", s.name, "uses"))
        if s.kind != "tool" and s.uses:
            diags.append(Diagnostic("CAP_ON_PURE", f"non-tool stage {s.name!r} cannot hold capabilities", s.name, "uses"))
        if (table is None or s.op in table) and s.kind in STAGE_KINDS:
            t = output_type(s)
            for i, c in enumerate(s.checks):
                if t != "any" and t not in PREDICATE_TYPES[c.op]:
                    diags.append(Diagnostic("PRED_TYPE", f"check {c.text()!r} does not apply to {t} output of {s.name!r}", s.name, "checks", i))

    if not any(d.code in ("UNKNOWN_DEP", "DUP_STAGE") for d in diags):
        cycle = find_cycle(p)
        if cycle:
            diags.append(Diagnostic("CYCLE", "dependency cycle: " + " -> ".join(cycle), cycle[0]))
    if not any(s.kind == "output" for s in p.stages):
        diags.append(Diagnostic("NO_TARGET", "program declares no output stage"))
    return diags


def find_cycle(p: Program) -> list[str] | None:
    deps = {s.name: s.after for s in p.stages}
    state: dict[str, int] = {}
    path: list[str] = []

    def dfs(n: str) -> list[str] | None:
        state[n] = 1
        path.append(n)
        for d in deps.get(n, ()):
            if state.get(d) == 1:
                return path[path.index(d):] + [d]
            if state.get(d) is None:
                found = dfs(d)
                if found:
                    return found
        state[n] = 2
        path.pop()
        return None

    for n in deps:
        if state.get(n) is None:
            found = dfs(n)
            if found:
                return found
    return None


def target_cone(p: Program) -> set[str]:
    """Output stages plus every stage they transitively depend on."""
    deps = {s.name: s.after for s in p.stages}
    cone: set[str] = set()
    stack = [s.name for s in p.stages if s.kind == "output"]
    while stack:
        n = stack.pop()
        if n not in cone:
            cone.add(n)
            stack.extend(deps[n])
    return cone


def levels(p: Program) -> list[list[str]]:
    """Kahn's algorithm, grouped by level (Eq. 1)."""
    indeg = {s.name: len(s.after) for s in p.stages}
    children: dict[str, list[str]] = {s.name: [] for s in p.stages}
    for s in p.stages:
        for d in s.after:
            children[d].append(s.name)
    level = sorted(n for n, k in indeg.items() if k == 0)
    out = []
    while level:
        out.append(level)
        nxt = []
        for n in level:
            for c in children[n]:
                indeg[c] -= 1
                if indeg[c] == 0:
                    nxt.append(c)
        level = sorted(nxt)
    return out


ANY = "*"


def footprint(s: Stage, resolve=None) -> tuple[set[str], set[str]]:
    """Local paths a stage may read and write.

    Arguments are compile-time constants, so the footprint of a built-in tool
    is static. Shell commands run in a write-denying sandbox, so they only
    read; custom tools are opaque and may touch anything. `resolve` maps a
    path to its real location (the runtime passes realpath under the working
    directory, so aliases through symbolic links compare equal).
    """
    if s.kind != "tool":
        return set(), set()
    path = s.arg("path")
    norm = resolve or (lambda x: posixpath.normpath(str(x)))
    target = ANY if path is None else norm(path)
    if s.op == "fs.read":
        return {target}, set()
    if s.op == "fs.write":
        return set(), {target}
    if s.op == "shell.run":
        return {ANY}, set()
    if s.op == "custom.call":
        return {ANY}, {ANY}
    return set(), set()


def _overlap(a: set[str], b: set[str]) -> bool:
    for x in a:
        for y in b:
            if ANY in (x, y) or x == y or x.startswith(y + "/") or y.startswith(x + "/"):
                return True
    return False


def conflicts(a: Stage, b: Stage, resolve=None) -> bool:
    """Write-write or read-write overlap between two stages' footprints."""
    (ra, wa), (rb, wb) = footprint(a, resolve), footprint(b, resolve)
    return _overlap(wa, wb) or _overlap(wa, rb) or _overlap(ra, wb)


def serialize_conflicts(p: Program, lv: list[list[str]], resolve=None) -> tuple[list[list[str]], list[Diagnostic]]:
    """Split each level so that no two conflicting stages share one.

    A stage goes to the sub-level after the last earlier stage (in level order)
    it conflicts with, so sequential and parallel execution apply conflicting
    effects in the same order.
    """
    by_name = {s.name: s for s in p.stages}
    out, warnings = [], []
    for level in lv:
        slot: dict[str, int] = {}
        for i, n in enumerate(level):
            earlier = [m for m in level[:i] if conflicts(by_name[m], by_name[n], resolve)]
            for m in earlier:
                warnings.append(Diagnostic("EFFECT_CONFLICT", f"{m!r} and {n!r} touch overlapping files in one level; "
                                           f"{m} runs before {n}", n))
            slot[n] = 1 + max((slot[m] for m in earlier), default=-1)
        for k in range(max(slot.values(), default=-1) + 1):
            out.append([n for n in level if slot[n] == k])
    return out, warnings


def effect_closed_cone(p: Program) -> set[str]:
    """The target cone, plus every stage that writes a file a kept stage may read, with its ancestors.

    Such writes reach the target through the file system rather than through
    a dependency, so pruning the writer could change what a kept stage reads.
    """
    cone = target_cone(p)
    deps = {s.name: s.after for s in p.stages}
    while True:
        reads = set().union(*(footprint(s)[0] for s in p.stages if s.name in cone))
        extra = [s.name for s in p.stages if s.name not in cone and _overlap(footprint(s)[1], reads)]
        if not extra:
            return cone
        stack = extra
        while stack:
            n = stack.pop()
            if n not in cone:
                cone.add(n)
                stack.extend(deps[n])


def compile_program(p: Program) -> IR:
    diags = validate(p)
    if diags:
        raise CompileError(diags)
    cone = effect_closed_cone(p)
    pruned = [s.name for s in p.stages if s.name not in cone]
    kept = Program(p.caps, tuple(s for s in p.stages if s.name in cone))
    used = sorted({u for s in kept.stages for u in s.uses})
    lv = levels(kept)
    return IR(
        program=kept,
        levels=lv,
        cap_index={name: i for i, name in enumerate(used)},
        targets=[s.name for s in kept.stages if s.kind == "output"],
        pruned=pruned,
        warnings=serialize_conflicts(kept, lv)[1],
    )


def emit(ir: IR) -> bytes:
    """Binary artifact: magic, version byte, SHA-256 of payload, msgpack payload."""
    payload = msgpack.packb(
        {"program": program_to_dict(ir.program), "levels": ir.levels,
         "cap_index": ir.cap_index, "targets": ir.targets},
        use_bin_type=True,
    )
    return MAGIC + bytes([FORMAT_VERSION]) + hashlib.sha256(payload).digest() + payload


def load(blob: bytes) -> IR:
    if blob[:3] != MAGIC:
        raise TdgError("not a TDG artifact")
    if blob[3] != FORMAT_VERSION:
        raise TdgError(f"unsupported artifact version {blob[3]}")
    want, payload = blob[4:36], blob[36:]
    if hashlib.sha256(payload).digest() != want:
        raise TdgError("artifact digest mismatch")
    d = msgpack.unpackb(payload, raw=False)
    return IR(program_from_dict(d["program"]), d["levels"], d["cap_index"], d["targets"])
