import pytest

from tdg.compiler import compile_program, validate
from tdg.core import TdgError, program_from_dict, program_to_dict
from tdg.ops import World
from tdg.parser import parse
from tdg.repair import (
    apply_patch, authority_requests_for_event, propose_for_diagnostic, propose_for_event, widens,
)
from tdg.runtime import run


def test_json_patch_ops():
    doc = {"a": [1, 2], "b": {"c": 1}}
    out = apply_patch(doc, [
        {"op": "add", "path": "/a/-", "value": 3},
        {"op": "replace", "path": "/b/c", "value": 2},
        {"op": "remove", "path": "/a/0"},
        {"op": "test", "path": "/b/c", "value": 2},
    ])
    assert out == {"a": [2, 3], "b": {"c": 2}} and doc == {"a": [1, 2], "b": {"c": 1}}
    with pytest.raises(TdgError):
        apply_patch(doc, [{"op": "test", "path": "/b/c", "value": 9}])


def _fix_compile(src):
    p = parse(src)
    doc = program_to_dict(p)
    d = validate(p)[0]
    best = propose_for_diagnostic(doc, d)[0]
    return program_from_dict(apply_patch(doc, best.patch))


def test_dependency_typo_renamed():
    fixed = _fix_compile('stage fetch:entry{arg value=1;}stage o:output{after fecth;}')
    assert fixed.stage("o").after == ("fetch",)
    compile_program(fixed)


def test_unknown_op_renamed():
    fixed = _fix_compile('stage a:entry{arg value="x";}stage n:transform cuont{after a;}stage o:output{after n;}')
    assert fixed.stage("n").op == "count"


def test_no_proposal_without_close_match():
    p = parse('stage a:entry{arg value=1;}stage o:output{after zzzzzz;}')
    assert propose_for_diagnostic(program_to_dict(p), validate(p)[0]) == []


def _violation(src, endpoints, workdir):
    ir = compile_program(parse(src))
    r = run(ir, workdir, World(endpoints))
    return program_to_dict(ir.program), r.events[0]


SRC = ('cap net n{allow "https://x.y/*";}'
       'stage f:tool net.get{uses n;arg url="https://x.y/a";check status 200;viol propose;}stage o:output{after f;}')


def test_success_code_relaxed_to_range(workdir):
    doc, ev = _violation(SRC, {"https://x.y/a": {"status": 201, "body": "x"}}, workdir)
    best = propose_for_event(doc, ev)[0]
    assert best.kind == "relax"
    assert apply_patch(doc, best.patch)["stages"][0]["checks"][0]["args"] == [200, 299]


def test_server_error_gets_retry(workdir):
    doc, ev = _violation(SRC, {"https://x.y/a": {"status": 503, "body": ""}}, workdir)
    assert propose_for_event(doc, ev)[0].kind == "retry"


def test_client_error_abstains(workdir):
    doc, ev = _violation(SRC, {"https://x.y/a": {"status": 404, "body": ""}}, workdir)
    assert propose_for_event(doc, ev) == []


def test_field_key_typo(workdir):
    src = ('cap net n{allow "https://x.y/*";}stage f:tool net.get{uses n;arg url="https://x.y/a";}'
           'stage k:transform field{after f;arg key="ordres";check nonempty;viol propose;}stage o:output{after k;}')
    doc, ev = _violation(src, {"https://x.y/a": {"status": 200, "body": '{"orders":[1]}'}}, workdir)
    best = propose_for_event(doc, ev)[0]
    assert apply_patch(doc, best.patch)["stages"][1]["args"]["key"] == "orders"


def test_denied_host_becomes_separate_authority_request(workdir):
    src = ('cap net n{allow "https://x.y/*";}stage f:tool net.get{uses n;arg url="https://z.y/a";fail propose;}'
           'stage o:output{after f;}')
    doc, ev = _violation(src, {}, workdir)
    assert propose_for_event(doc, ev) == []
    (req,) = authority_requests_for_event(doc, ev)
    assert req.widens and "z.y" in req.widens[0]


def test_widening_detected_from_patch_not_kind():
    doc = program_to_dict(parse('cap fs a{root "out";mode write;}cap fs b{root ".";mode rw;}'
                                'stage w:tool fs.write{uses a;arg path="out/x";}stage o:output{after w;}'))
    swap = apply_patch(doc, [{"op": "replace", "path": "/stages/0/uses/0", "value": "b"}])
    narrow = apply_patch(doc, [{"op": "replace", "path": "/caps/0/root", "value": "out/sub"}])
    assert widens(doc, swap) and not widens(doc, narrow)


def test_cost_ranking_prefers_candidates_that_compile():
    p = parse('stage fetch:entry{arg value=1;}stage fetcher:entry{arg value=2;}'
              'stage o:output{after fecth;in fetch;}')
    doc, d = program_to_dict(p), validate(p)[0]
    by_cost = propose_for_diagnostic(doc, d, rank="cost")
    assert by_cost[0].cost <= by_cost[-1].cost
    assert apply_patch(doc, by_cost[0].patch)["stages"][2]["after"] == ["fetch"]
