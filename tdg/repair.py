"""Structured repair proposals.

A proposal is an RFC 6902 JSON Patch against the program's dict form, plus a
reason, a kind and a confidence in [0, 1]. Proposals are never applied by the
runtime; a supervisor accepts or rejects them.

Any proposal after which some stage could reach something it could not reach
before is an authority request. Requests are computed by comparing per-stage
authority before and after the patch, not from the proposal's kind; they are
never ranked with ordinary proposals and need a separate grant to apply.
"""

from __future__ import annotations

import copy
import difflib
import fnmatch
import json
import posixpath
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from .compiler import Diagnostic, validate
from .core import BRANCHES, TOOLS, TRANSFORMS, TdgError, program_from_dict


@dataclass(frozen=True)
class Proposal:
    patch: list[dict]
    reason: str
    kind: str  # rename | relax | retry | authority
    confidence: float
    widens: tuple[str, ...] = ()  # why the patch grants new authority, if it does
    cost: float = 0.0


# ------------------------------------------------------------ JSON Patch

def _split(path: str) -> list[str]:
    if not path.startswith("/"):
        raise TdgError(f"bad JSON pointer {path!r}")
    return [p.replace("~1", "/").replace("~0", "~") for p in path[1:].split("/")]


def apply_patch(doc: dict, patch: list[dict]) -> dict:
    """Apply the add/replace/remove/test subset of RFC 6902."""
    doc = copy.deepcopy(doc)
    for op in patch:
        *parents, last = _split(op["path"])
        target = doc
        for key in parents:
            target = target[int(key)] if isinstance(target, list) else target.setdefault(key, {})
        kind = op["op"]
        if isinstance(target, list):
            idx = len(target) if last == "-" else int(last)
            if kind == "add":
                target.insert(idx, op["value"])
            elif kind == "replace":
                target[idx] = op["value"]
            elif kind == "remove":
                del target[idx]
            elif kind == "test" and target[idx] != op["value"]:
                raise TdgError(f"test failed at {op['path']}")
        else:
            if kind in ("add", "replace"):
                target[last] = op["value"]
            elif kind == "remove":
                del target[last]
            elif kind == "test" and target.get(last) != op["value"]:
                raise TdgError(f"test failed at {op['path']}")
    return doc


# ------------------------------------------------------------ authority

_MODES = {"read": {"read"}, "write": {"write"}, "rw": {"read", "write"}}


def _net_covered(new: str, old: str) -> bool:
    a, b = urlsplit(new), urlsplit(old)
    return ((a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)
            and fnmatch.fnmatchcase(a.path or "/", b.path or "/"))


def _cap_covered(new: dict, old: dict) -> bool:
    """Is every operation `new` permits also permitted by `old`?"""
    if new["kind"] != old["kind"]:
        return False
    k = new["kind"]
    if k == "net":
        return all(any(_net_covered(n, o) for o in old.get("allow", [])) for n in new.get("allow", []))
    if k == "shell":
        return set(new.get("allow", [])) <= set(old.get("allow", []))
    if k == "fs":
        nr, orr = posixpath.normpath(new.get("root", "")), posixpath.normpath(old.get("root", ""))
        inside = nr == orr or nr.startswith(orr + "/") or orr == "."
        return inside and _MODES.get(new.get("mode"), {"?"}) <= _MODES.get(old.get("mode"), set())
    if k == "model":
        return new.get("model_id") == old.get("model_id") and (new.get("max_tokens") or 0) <= (old.get("max_tokens") or 0)
    return new == {**old, "name": new["name"]}


def authority(doc: dict) -> dict[str, list[dict]]:
    """The capabilities each stage holds (undefined names grant nothing)."""
    caps = {c["name"]: c for c in doc.get("caps", [])}
    return {s["name"]: [caps[u] for u in s.get("uses", []) if u in caps] for s in doc.get("stages", [])}


def widens(before: dict, after: dict) -> list[str]:
    """Reasons `after` lets some stage reach more than it could in `before`."""
    old, new = authority(before), authority(after)
    reasons = []
    for stage, held in new.items():
        for cap in held:
            if not any(_cap_covered(cap, o) for o in old.get(stage, [])):
                reasons.append(f"stage {stage!r} gains {cap['kind']} capability {cap['name']!r}"
                               f" ({', '.join(cap.get('allow', [])) or cap.get('root') or cap.get('model_id') or '-'})")
    return reasons


# ------------------------------------------------------------ ranking

_KIND_COST = {"rename": 0.0, "retry": 1.0, "relax": 2.0, "authority": 3.0}


def cost(doc: dict, p: Proposal) -> float:
    """Lower is better: remaining compile errors, constraint weakening, distance, size."""
    try:
        patched = apply_patch(doc, p.patch)
        errors = len(validate(program_from_dict(patched)))
    except Exception:  # noqa: BLE001 - an unappliable patch is the worst candidate
        return float("inf")
    edits = sum(op["op"] != "test" for op in p.patch)
    distance = 1 - p.confidence if p.kind == "rename" else 0.0
    return 10 * errors + _KIND_COST.get(p.kind, 2.0) + distance + 0.1 * edits


def _finish(doc: dict, props: list[Proposal], grants: bool, rank: str) -> list[Proposal]:
    tagged = []
    for p in props:
        try:
            why = tuple(widens(doc, apply_patch(doc, p.patch)))
        except Exception:  # noqa: BLE001
            why = ()
        tagged.append(replace(p, widens=why, cost=round(cost(doc, p), 3)))
    keep = [p for p in tagged if bool(p.widens) == grants]
    if rank == "cost":
        return sorted(keep, key=lambda p: (p.cost, -p.confidence))
    return sorted(keep, key=lambda p: -p.confidence)


# ------------------------------------------------------------ helpers

def _index(doc: dict, stage: str) -> int:
    for i, s in enumerate(doc["stages"]):
        if s["name"] == stage:
            return i
    raise KeyError(stage)


def _close(word: str, options, n: int = 3) -> list[tuple[str, float]]:
    scored = [(o, difflib.SequenceMatcher(None, word, o).ratio()) for o in options if o != word]
    scored = [x for x in scored if x[1] >= 0.6]
    return sorted(scored, key=lambda x: (-x[1], x[0]))[:n]


def _rename(doc: dict, d: Diagnostic, options) -> list[Proposal]:
    i = _index(doc, d.stage)
    path = f"/stages/{i}/{d.field}" + (f"/{d.index}" if d.index is not None else "")
    return [
        Proposal([{"op": "test", "path": path, "value": d.value}, {"op": "replace", "path": path, "value": o}],
                 f"{d.value!r} is undefined; did you mean {o!r}?", "rename", round(r, 3))
        for o, r in _close(d.value, options)
    ]


# ------------------------------------------------------------ compile time

def propose_for_diagnostic(doc: dict, d: Diagnostic, rank: str = "confidence") -> list[Proposal]:
    """Ordinary proposals for a compile-time diagnostic (no authority requests)."""
    return _finish(doc, _diagnostic_candidates(doc, d), False, rank)


def authority_requests_for_diagnostic(doc: dict, d: Diagnostic) -> list[Proposal]:
    return _finish(doc, _diagnostic_candidates(doc, d), True, "confidence")


def _diagnostic_candidates(doc: dict, d: Diagnostic) -> list[Proposal]:
    stages = {s["name"]: s for s in doc["stages"]}
    if d.code == "UNKNOWN_DEP":
        return _rename(doc, d, [n for n in stages if n != d.stage])
    if d.code == "UNKNOWN_INPUT":
        deps = stages[d.stage].get("after", [])
        return _rename(doc, d, [stages[x].get("out", x) for x in deps if x in stages])
    if d.code == "UNKNOWN_CAP":
        return _rename(doc, d, [c["name"] for c in doc["caps"]])
    if d.code == "UNKNOWN_OP":
        kind = stages[d.stage]["kind"]
        table = {"tool": TOOLS, "transform": TRANSFORMS, "branch": BRANCHES}[kind]
        return _rename(doc, d, list(table))
    return []


# ------------------------------------------------------------ run time

def _json_view(v):
    if isinstance(v, dict) and set(v) == {"status", "body"}:
        v = v["body"]
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return None
    return v


def _next_pow2(n: int) -> int:
    p = 1
    while p < n:
        p *= 2
    return p


def propose_for_event(doc: dict, ev: dict, rank: str = "confidence") -> list[Proposal]:
    """Ordinary proposals for a runtime event (no authority requests)."""
    return _finish(doc, _event_candidates(doc, ev), False, rank)


def authority_requests_for_event(doc: dict, ev: dict) -> list[Proposal]:
    return _finish(doc, _event_candidates(doc, ev), True, "confidence")


def _event_candidates(doc: dict, ev: dict) -> list[Proposal]:
    i = _index(doc, ev["stage"])
    stage = doc["stages"][i]
    out: list[Proposal] = []

    if ev["type"] == "violation":
        j = ev["check_index"]
        chk = stage["checks"][j]
        obs = ev["observed"]
        cpath = f"/stages/{i}/checks/{j}"
        if chk["op"] == "status" and isinstance(obs, int):
            lo, hi = chk["args"]
            if 500 <= obs < 600:
                out.append(Proposal(
                    [{"op": "add", "path": f"/stages/{i}/on_violation", "value": {"action": "retry", "count": 3}}],
                    f"server error {obs} is often transient; retry up to 3 times", "retry", 0.6))
            elif 200 <= obs < 300 and 200 <= lo <= hi < 300:
                out.append(Proposal(
                    [{"op": "replace", "path": cpath, "value": {"op": "status", "args": [200, 299]}}],
                    f"status {obs} is a success code; accept the 2xx range", "relax", 0.8))
            # 4xx responses have no safe single-edit fix; abstain.
        elif chk["op"] == "maxbytes" and isinstance(obs, int):
            new = _next_pow2(obs)
            out.append(Proposal(
                [{"op": "replace", "path": cpath, "value": {"op": "maxbytes", "args": [new]}}],
                f"output is {obs} bytes; raise the limit to {new}", "relax", 0.5))
        elif chk["op"] in ("max", "min") and isinstance(obs, (int, float)):
            out.append(Proposal(
                [{"op": "replace", "path": cpath, "value": {"op": chk["op"], "args": [obs]}}],
                f"observed {obs}; move the {chk['op']} bound to it", "relax", 0.4))
        elif chk["op"] == "nonempty" and stage.get("op") == "field":
            src = _json_view(ev["inputs"][0]) if ev.get("inputs") else None
            want = str(stage.get("args", {}).get("key", ""))
            *prefix, want = want.split(".")
            for key in prefix:
                src = src.get(key) if isinstance(src, dict) else None
            keys = list(src) if isinstance(src, dict) else []
            prefix = "".join(f"{k}." for k in prefix)
            for k, r in _close(want, keys):
                out.append(Proposal(
                    [{"op": "replace", "path": f"/stages/{i}/args/key", "value": prefix + k}],
                    f"input has no key {want!r}; did you mean {k!r}?", "rename", round(r, 3)))
    elif ev["type"] == "denied":
        cap_name = next((u for u in stage.get("uses", [])
                         for c in doc["caps"] if c["name"] == u and c["kind"] == ev["kind"]), None)
        if cap_name is not None and ev["kind"] == "net":
            parts = urlsplit(ev["target"])
            if parts.scheme and parts.hostname:
                k = next(n for n, c in enumerate(doc["caps"]) if c["name"] == cap_name)
                pattern = f"{parts.scheme}://{parts.netloc}{parts.path}"
                out.append(Proposal(
                    [{"op": "add", "path": f"/caps/{k}/allow/-", "value": pattern}],
                    f"widen {cap_name!r} to allow {pattern} (grants new authority)", "authority", 0.3))
        elif cap_name is not None and ev["kind"] == "shell":
            k = next(n for n, c in enumerate(doc["caps"]) if c["name"] == cap_name)
            out.append(Proposal(
                [{"op": "add", "path": f"/caps/{k}/allow/-", "value": ev["target"]}],
                f"allow exactly {ev['target']!r} under {cap_name!r} (grants new authority)", "authority", 0.3))
    return out
