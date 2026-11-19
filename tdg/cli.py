"""Command-line projection: the supervisor's interface to graphs and traces."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .compiler import CompileError, compile_program, emit, load, validate
from .core import program_from_dict, program_to_dict
from .ops import World
from .parser import parse, to_text
from .repair import (
    apply_patch, authority_requests_for_diagnostic, authority_requests_for_event,
    propose_for_diagnostic, propose_for_event, widens,
)
from .runtime import run

TEMPLATE = """/* goal: describe the target here */
cap net api{allow "https://api.example.com/*";}
stage fetch:tool net.get{uses api;arg url="https://api.example.com/items";out resp;check status 200..299;viol propose;}
stage items:transform field{after fetch;in resp;arg key="items";check nonempty;viol propose;}
stage result:output{after items;}
"""


def _load_any(path: str):
    data = Path(path).read_bytes()
    if data[:3] == b"TDG":
        return None, load(data)
    program = parse(data.decode())
    return program, None


def _world(path: str | None) -> World:
    if not path:
        return World()
    return World(json.loads(Path(path).read_text()))


def cmd_init(a):
    Path(a.file).write_text(TEMPLATE)
    print(f"wrote {a.file}")


def cmd_fmt(a):
    print(to_text(parse(Path(a.file).read_text())), end="")


def cmd_check(a):
    program = parse(Path(a.file).read_text())
    diags = validate(program)
    doc = program_to_dict(program)
    report = [{**asdict(d), "proposals": [asdict(p) for p in propose_for_diagnostic(doc, d)],
               "authority_requests": [asdict(p) for p in authority_requests_for_diagnostic(doc, d)]} for d in diags]
    print(json.dumps(report, indent=2) if report else "ok")
    return 1 if diags else 0


def cmd_build(a):
    ir = compile_program(parse(Path(a.file).read_text()))
    blob = emit(ir)
    Path(a.out).write_bytes(blob)
    print(f"wrote {a.out} ({len(blob)} bytes, {len(ir.levels)} levels, pruned {ir.pruned or 'none'})")


def cmd_run(a):
    program, ir = _load_any(a.file)
    if ir is None:
        try:
            ir = compile_program(program)
        except CompileError as e:
            return cmd_check(argparse.Namespace(file=a.file))
    result = run(ir, a.workdir, _world(a.world), parallel=a.par)
    doc = program_to_dict(ir.program)
    report = result.to_json()
    report["proposals"] = [
        {"stage": ev["stage"], **asdict(p)} for ev in result.events for p in propose_for_event(doc, ev)
    ]
    report["authority_requests"] = [
        {"stage": ev["stage"], **asdict(p)} for ev in result.events for p in authority_requests_for_event(doc, ev)
    ]
    if a.trace:
        Path(a.trace).write_text(json.dumps(report, indent=2, default=str))
    print(f"target {result.status}; digest {result.final_digest[:16]}")
    for name, tr in result.traces.items():
        if tr.status != "ok":
            print(f"  {name}: {tr.status}" + (f" ({tr.error})" if tr.error else ""))
    for n, p in enumerate(report["proposals"]):
        print(f"  proposal {n} [{p['kind']}, confidence {p['confidence']}]: {p['reason']}")
    for n, p in enumerate(report["authority_requests"]):
        print(f"  authority request {n} (needs accept --grant-authority): {'; '.join(p['widens'])}")
    return 0 if result.determined else 2


def cmd_explain(a):
    report = json.loads(Path(a.trace).read_text())
    tr = report["stages"][a.stage]
    print(json.dumps(tr, indent=2))
    for p in report.get("proposals", []):
        if p["stage"] == a.stage:
            print(f"suggested fix: {p['reason']}")


def cmd_accept(a):
    report = json.loads(Path(a.trace).read_text())
    proposal = report["authority_requests" if a.grant_authority else "proposals"][a.index]
    doc = program_to_dict(parse(Path(a.file).read_text()))
    patched = apply_patch(doc, proposal["patch"])
    reasons = widens(doc, patched)
    if reasons and not a.grant_authority:
        print("refused: this patch grants new authority and needs --grant-authority:\n  " + "\n  ".join(reasons))
        return 3
    Path(a.file).write_text(to_text(program_from_dict(patched)))
    print(f"applied {'authority request' if a.grant_authority else 'proposal'} {a.index} to {a.file}: {proposal['reason']}")
    for r in reasons:
        print(f"  granted: {r}")


def cmd_diff(a):
    old = {s["name"]: s for s in program_to_dict(parse(Path(a.old).read_text()))["stages"]}
    new = {s["name"]: s for s in program_to_dict(parse(Path(a.new).read_text()))["stages"]}
    for n in sorted(old.keys() - new.keys()):
        print(f"- stage {n}")
    for n in sorted(new.keys() - old.keys()):
        print(f"+ stage {n}")
    for n in sorted(old.keys() & new.keys()):
        for k in sorted(old[n].keys() | new[n].keys()):
            if old[n].get(k) != new[n].get(k):
                print(f"~ {n}.{k}: {old[n].get(k)!r} -> {new[n].get(k)!r}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tdg")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn, args in [
        ("init", cmd_init, ["file"]),
        ("fmt", cmd_fmt, ["file"]),
        ("check", cmd_check, ["file"]),
        ("explain", cmd_explain, ["trace", "stage"]),
        ("diff", cmd_diff, ["old", "new"]),
    ]:
        p = sub.add_parser(name)
        for x in args:
            p.add_argument(x)
        p.set_defaults(fn=fn)
    p = sub.add_parser("build")
    p.add_argument("file")
    p.add_argument("-o", "--out", required=True)
    p.set_defaults(fn=cmd_build)
    p = sub.add_parser("run")
    p.add_argument("file")
    p.add_argument("--par", action="store_true")
    p.add_argument("--world")
    p.add_argument("--workdir", default=".")
    p.add_argument("--trace")
    p.set_defaults(fn=cmd_run)
    p = sub.add_parser("accept")
    p.add_argument("file")
    p.add_argument("trace")
    p.add_argument("index", type=int)
    p.add_argument("--grant-authority", action="store_true",
                   help="apply an entry from authority_requests, which widens what a stage may reach")
    p.set_defaults(fn=cmd_accept)
    a = ap.parse_args(argv)
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())
