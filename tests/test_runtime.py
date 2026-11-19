import json

import pytest
import workloads

from tdg.compiler import compile_program
from tdg.ops import World
from tdg.parser import parse
from tdg.runtime import run


def run_src(src, workdir, endpoints=None, parallel=False):
    return run(compile_program(parse(src)), workdir, World(endpoints or {}), parallel=parallel)


@pytest.mark.parametrize("name", sorted(workloads.SOURCES))
def test_workloads_determine_target(name, workdir):
    r = run(compile_program(parse(workloads.SOURCES[name])), workdir, World(workloads.endpoints(name)))
    assert r.status == "determined"


@pytest.mark.parametrize("name", sorted(workloads.SOURCES))
def test_sequential_and_parallel_agree(name, workdir):
    ir = compile_program(parse(workloads.SOURCES[name]))
    seq = run(ir, workdir, World(workloads.endpoints(name)))
    par = run(ir, workdir, World(workloads.endpoints(name)), parallel=True)
    assert seq.final_digest == par.final_digest


CONFLICT = ('cap fs out{root "out";mode write;}'
            'stage a:tool fs.write{uses out;arg path="out/x.txt",text="from a";}'
            'stage b:tool fs.write{uses out;arg path="out/./x.txt",text="from b";}'
            'stage o:output{after a,b;}')


def test_conflicting_writes_are_serialized(workdir):
    ir = compile_program(parse(CONFLICT))
    assert [w.code for w in ir.warnings] == ["EFFECT_CONFLICT"]
    for parallel in (False, True):
        for _ in range(20):
            run(ir, workdir, World(storage_jitter_s=0.002), parallel=parallel)
            assert open(f"{workdir}/out/x.txt").read() == "from b"


def test_conflicts_resolved_through_symlinks(workdir):
    import os
    os.symlink(os.path.join(workdir, "out"), os.path.join(workdir, "out", "alias"))
    src = CONFLICT.replace('out/./x.txt', 'out/alias/x.txt')
    ir = compile_program(parse(src))
    assert ir.warnings == []  # lexically distinct paths
    from tdg.runtime import Runtime
    assert Runtime(ir, workdir).plan == [["a"], ["b"], ["o"]]


def test_writer_feeding_a_kept_reader_is_not_pruned(workdir):
    src = ('cap fs out{root "out";mode rw;}'
           'stage w:tool fs.write{uses out;arg path="out/x.txt",text="hello";}'
           'stage side:tool fs.write{uses out;arg path="out/y.txt",text="unused";}'
           'stage r:tool fs.read{after w;uses out;arg path="out/x.txt";}'
           'stage w2:tool fs.write{uses out;arg path="out/z.txt",text="z";}'
           'stage rz:tool fs.read{uses out;arg path="out/z.txt";fail propose;}'
           'stage o:output{after r,rz;}')
    ir = compile_program(parse(src))
    assert ir.pruned == ["side"]


def test_stage_timing_breakdown(workdir):
    r = run(compile_program(parse(workloads.W1)), workdir, World(workloads.endpoints("W1")))
    t = r.traces["fetch"].timing
    assert set(t) == {"issue_us", "gate_us", "work_us", "predicate_us", "trace_us"} and t["gate_us"] > 0


def test_branch_skips_other_arm(workdir):
    r = run(compile_program(parse(workloads.W3)), workdir, World(workloads.endpoints("W3")))
    assert r.traces["triage"].status == "ok"
    assert r.traces["quiet"].status == "skipped" and r.traces["report"].status == "skipped"


def test_values_are_passed_by_copy(workdir):
    src = ('stage a:entry{arg x=1;}stage b:transform merge{after a;}stage c:transform identity{after a;}'
           'stage o:output{after b,c;}')
    r = run_src(src, workdir)
    assert r.outputs["a"] == {"x": 1}
    assert r.outputs["b"] == {"0": {"x": 1}}


def test_violation_with_propose_blocks_descendants(workdir):
    src = ('cap net n{allow "https://x.y/*";}'
           'stage f:tool net.get{uses n;arg url="https://x.y/a";check status 200;viol propose;}'
           'stage b:transform body{after f;}stage o:output{after b;}')
    r = run_src(src, workdir, {"https://x.y/a": {"status": 204, "body": ""}})
    assert r.status == "needs_approval"
    assert r.traces["f"].status == "violated" and r.traces["b"].status == "blocked"
    assert r.events[0]["observed"] == 204


def test_violation_with_abort_stops_run(workdir):
    src = ('cap net n{allow "https://x.y/*";}'
           'stage f:tool net.get{uses n;arg url="https://x.y/a";check status 200;}stage o:output{after f;}')
    assert run_src(src, workdir).status == "aborted"


def test_retry_policy_recovers_transient_error(workdir):
    src = ('cap net n{allow "https://x.y/*";}'
           'stage f:tool net.get{uses n;arg url="https://x.y/a";check status 200;viol retry 2;}stage o:output{after f;}')
    seq = [{"status": 503, "body": ""}, {"status": 503, "body": ""}, {"status": 200, "body": "ok"}]
    r = run_src(src, workdir, {"https://x.y/a": seq})
    assert r.status == "determined" and r.traces["f"].attempts == 3


def test_capability_denial_is_a_failure_not_a_crash(workdir):
    src = ('cap fs d{root "data";mode read;}'
           'stage f:tool fs.read{uses d;arg path="private/secret.txt";fail propose;}stage o:output{after f;}')
    r = run_src(src, workdir)
    assert r.traces["f"].status == "failed" and "outside declared root" in r.traces["f"].error
    assert r.events[0]["type"] == "denied"


def test_trace_records_hashes_and_provenance(workdir):
    r = run(compile_program(parse(workloads.W1)), workdir, World(workloads.endpoints("W1")))
    t = r.traces["orders"]
    assert t.input_hash and t.output_hash
    assert t.provenance == [{"stage": "fetch", "output_hash": r.traces["fetch"].output_hash}]
    assert all(c["ok"] for c in r.traces["fetch"].checks)
    json.dumps(r.to_json(), default=str)


def test_stochastic_stage_breaks_replay(workdir):
    src = ('cap model m{id "mock-1";tokens 100;}stage a:entry{arg value="hi";}'
           'stage g:tool model.call{after a;uses m;arg model="mock-1";rand;}stage o:output{after g;}')
    ir = compile_program(parse(src))
    r1, r2 = run(ir, workdir, World()), run(ir, workdir, World())
    assert not r1.replayable and r1.final_digest != r2.final_digest


def test_model_tokens_traced(workdir):
    r = run(compile_program(parse(workloads.W2)), workdir, World(workloads.endpoints("W2")))
    assert r.traces["summary"].model_tokens > 0
