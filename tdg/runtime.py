"""Level scheduler, constraint checking, policies and traces."""

from __future__ import annotations

import copy
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .capabilities import CapabilityDenied, Enforcer, Gate
from .compiler import IR, serialize_conflicts
from .core import Predicate, Stage, digest
from .ops import BRANCH_IMPLS, TRANSFORM_IMPLS, World, _as_text, run_tool


@dataclass
class StageTrace:
    stage: str
    status: str  # ok | violated | failed | skipped | blocked
    attempts: int = 0
    input_hash: str | None = None
    output_hash: str | None = None
    checks: list[dict] = field(default_factory=list)
    wall_ms: float = 0.0
    model_tokens: int = 0
    error: str | None = None
    provenance: list[dict] = field(default_factory=list)
    # microseconds: token issue, capability checks, tool work, predicates, hashing and copying
    timing: dict[str, float] = field(default_factory=dict)


@dataclass
class RunResult:
    status: str  # determined | needs_approval | aborted
    traces: dict[str, StageTrace]
    outputs: dict[str, Any]
    events: list[dict]
    final_digest: str
    replayable: bool

    @property
    def determined(self) -> bool:
        return self.status == "determined"

    def to_json(self) -> dict:
        return {
            "status": self.status,
            "final_digest": self.final_digest,
            "replayable": self.replayable,
            "stages": {k: vars(v) for k, v in self.traces.items()},
            "events": self.events,
        }


def check(pred: Predicate, value: Any) -> tuple[bool, Any]:
    if pred.op == "status":
        s = value.get("status") if isinstance(value, dict) else None
        return (s is not None and pred.args[0] <= s <= pred.args[1]), s
    if pred.op == "maxbytes":
        n = len(_as_text(value).encode())
        return n <= pred.args[0], n
    if pred.op == "nonempty":
        v = value["body"] if isinstance(value, dict) and set(value) == {"status", "body"} else value
        return v not in (None, "", [], {}), (len(v) if hasattr(v, "__len__") else v)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False, value
    if pred.op == "max":
        return value <= pred.args[0], value
    if pred.op == "min":
        return value >= pred.args[0], value
    raise ValueError(pred.op)


def _frozen(v: Any) -> Any:
    return json.loads(json.dumps(v))


class Runtime:
    def __init__(self, ir: IR, workdir: str, world: World | None = None, parallel: bool = False,
                 serialize: bool = True, enforcer: Enforcer | None = None):
        self.ir = ir
        self.world = world or World()
        self.parallel = parallel
        self.enforcer = enforcer or Enforcer(workdir)
        self.stages = {s.name: s for s in ir.program.stages}
        self.caps = {c.name: c for c in ir.program.caps}
        root = self.enforcer.workdir
        resolve = lambda p: os.path.realpath(os.path.join(root, str(p)))  # noqa: E731
        self.plan = serialize_conflicts(ir.program, ir.levels, resolve)[0] if serialize else ir.levels

    # ------------------------------------------------------------ one stage
    def _inputs(self, s: Stage, outputs: dict[str, Any]) -> list[Any]:
        if s.inputs:
            names = list(s.inputs)
        else:
            names = [self.stages[d].output_name for d in s.after if d != s.when]
        return [copy.deepcopy(outputs[n]) for n in names]

    def _execute(self, s: Stage, inputs: list[Any], gate: Gate) -> tuple[Any, int]:
        args = dict(s.args)
        if s.kind == "entry":
            return (args["value"] if set(args) == {"value"} else args), 0
        if s.kind == "tool":
            return run_tool(s.op, args, inputs, gate, s.stochastic)
        if s.kind == "transform":
            return TRANSFORM_IMPLS[s.op](inputs, args), 0
        if s.kind == "branch":
            return BRANCH_IMPLS[s.op](inputs, args), 0
        if s.kind == "output":
            if len(inputs) == 1:
                return inputs[0], 0
            names = list(s.inputs) or [self.stages[d].output_name for d in s.after]
            return dict(zip(names, inputs)), 0
        raise ValueError(s.kind)

    def _run_stage(self, s: Stage, outputs: dict, traces: dict) -> tuple[StageTrace, Any, dict | None]:
        t0 = time.perf_counter_ns()
        tr = StageTrace(s.name, "ok")
        inputs = self._inputs(s, outputs)
        tr.input_hash = digest(inputs)
        tr.provenance = [{"stage": d, "output_hash": traces[d].output_hash} for d in s.after]
        t1 = time.perf_counter_ns()
        tokens = [self.enforcer.issue(s.name, self.caps[u]) for u in s.uses]
        gate = Gate(self.enforcer, s.name, tokens, self.world)
        t2 = time.perf_counter_ns()
        work_ns = check_ns = freeze_ns = 0
        event = None
        fail_budget = s.on_fail.count if s.on_fail.action == "retry" else 0
        viol_budget = s.on_violation.count if s.on_violation.action == "retry" else 0
        value = None
        while True:
            tr.attempts += 1
            try:
                ta = time.perf_counter_ns()
                value, used = self._execute(s, inputs, gate)
                tb = time.perf_counter_ns()
                work_ns += tb - ta
                tr.model_tokens += used
                value = _frozen(value)
                freeze_ns += time.perf_counter_ns() - tb
            except CapabilityDenied as e:
                tr.status, tr.error = "failed", str(e)
                event = {"type": "denied", "stage": s.name, "kind": e.kind,
                         "target": e.target, "reason": e.reason, "policy": s.on_fail.action}
                break
            except Exception as e:  # noqa: BLE001 - tool failures become trace values
                if fail_budget > 0:
                    fail_budget -= 1
                    continue
                tr.status, tr.error = "failed", f"{type(e).__name__}: {e}"
                event = {"type": "failure", "stage": s.name, "error": tr.error, "policy": s.on_fail.action}
                break
            tc = time.perf_counter_ns()
            results = [(i, p, *check(p, value)) for i, p in enumerate(s.checks)]
            check_ns += time.perf_counter_ns() - tc
            tr.checks = [{"check": p.text(), "ok": ok, "observed": obs} for _, p, ok, obs in results]
            bad = [(i, p, obs) for i, p, ok, obs in results if not ok]
            if not bad:
                tr.status = "ok"
                break
            if viol_budget > 0:
                viol_budget -= 1
                continue
            i, p, obs = bad[0]
            tr.status = "violated"
            event = {"type": "violation", "stage": s.name, "check_index": i, "check": p.text(),
                     "observed": obs, "inputs": inputs, "value": value,
                     "policy": s.on_violation.action}
            break
        t3 = time.perf_counter_ns()
        tr.output_hash = digest(value) if tr.status == "ok" else None
        t4 = time.perf_counter_ns()
        gate_ns = gate.check_ns
        tr.timing = {
            "issue_us": (t2 - t1) / 1e3,
            "gate_us": gate_ns / 1e3,
            "work_us": max(0, work_ns - gate_ns) / 1e3,
            "predicate_us": check_ns / 1e3,
            "trace_us": ((t1 - t0) + freeze_ns + (t4 - t3)) / 1e3,
        }
        tr.wall_ms = (t4 - t0) / 1e6
        return tr, value, event

    # ------------------------------------------------------------ the graph
    def run(self) -> RunResult:
        outputs: dict[str, Any] = {}
        traces: dict[str, StageTrace] = {}
        events: list[dict] = []
        aborted = False
        width = max((len(level) for level in self.plan), default=1)
        pool = ThreadPoolExecutor(max_workers=width) if self.parallel else None
        try:
            for level in self.plan:
                if aborted:
                    break
                ready = []
                for name in level:
                    s = self.stages[name]
                    dep_status = {traces[d].status for d in s.after}
                    if "skipped" in dep_status and dep_status <= {"ok", "skipped"}:
                        traces[name] = StageTrace(name, "skipped")
                    elif dep_status - {"ok", "skipped"}:
                        traces[name] = StageTrace(name, "blocked")
                    elif s.when is not None and outputs.get(self.stages[s.when].output_name) is not True:
                        traces[name] = StageTrace(name, "skipped")
                    else:
                        ready.append(s)
                if pool is not None and len(ready) > 1:
                    done = list(pool.map(lambda s: self._run_stage(s, outputs, traces), ready))
                else:
                    done = [self._run_stage(s, outputs, traces) for s in ready]
                for s, (tr, value, event) in zip(ready, done):
                    traces[s.name] = tr
                    if tr.status == "ok":
                        outputs[s.output_name] = value
                    if event is not None:
                        events.append(event)
                        if event["policy"] != "propose":
                            aborted = True
        finally:
            if pool is not None:
                pool.shutdown()

        for level in self.plan:
            for name in level:
                traces.setdefault(name, StageTrace(name, "blocked"))
        statuses = {t.status for t in traces.values()}
        target_ok = any(traces[t].status == "ok" for t in self.ir.targets)
        if aborted:
            status = "aborted"
        elif statuses <= {"ok", "skipped"} and target_ok:
            status = "determined"
        else:
            status = "needs_approval"
        ok_hashes = {n: t.output_hash for n, t in sorted(traces.items()) if t.status == "ok"}
        replayable = not any(self.stages[n].stochastic for n, t in traces.items() if t.status == "ok")
        return RunResult(status, traces, outputs, events, digest(ok_hashes), replayable)


def run(ir: IR, workdir: str, world: World | None = None, parallel: bool = False,
        serialize: bool = True, enforcer: Enforcer | None = None) -> RunResult:
    return Runtime(ir, workdir, world, parallel, serialize, enforcer).run()
