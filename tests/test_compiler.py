import pytest
import workloads

from tdg.compiler import CompileError, compile_program, emit, load, validate
from tdg.core import TdgError
from tdg.parser import parse


def codes(text):
    return sorted(d.code for d in validate(parse(text)))


def test_unknown_dependency():
    assert codes('stage a:entry{arg value=1;}stage o:output{after b;}') == ["UNKNOWN_DEP"]


def test_self_dependency():
    assert "SELF_DEP" in codes('stage a:transform identity{after a;}stage o:output{after a;}')


def test_cycle_detected():
    c = codes('stage a:transform identity{after b;}stage b:transform identity{after a;}stage o:output{after a;}')
    assert c == ["CYCLE"]


def test_unknown_input_port():
    assert codes('stage a:entry{out x;arg value=1;}stage o:output{after a;in y;}') == ["UNKNOWN_INPUT"]


def test_tool_needs_matching_capability():
    c = codes('cap fs d{root "d";mode read;}stage f:tool net.get{uses d;arg url="https://x.y/";}stage o:output{after f;}')
    assert c == ["NO_CAP"]


def test_pure_stage_cannot_hold_capability():
    c = codes('cap net n{allow "https://x.y/*";}stage t:transform identity{uses n;}stage o:output{after t;}')
    assert c == ["CAP_ON_PURE"]


def test_predicate_type_checked():
    c = codes('stage n:transform count{check status 200;}stage o:output{after n;}')
    assert c == ["PRED_TYPE"]


def test_unknown_op_and_cap():
    c = codes('stage t:transform cuont{}stage f:tool net.get{uses nope;arg url="https://x.y/";}stage o:output{after t,f;}')
    assert c == ["NO_CAP", "UNKNOWN_CAP", "UNKNOWN_OP"]


def test_when_must_reference_branch_dependency():
    c = codes('stage a:entry{arg value=1;}stage t:transform identity{after a;when a;}stage o:output{after t;}')
    assert c == ["BAD_WHEN"]


def test_program_needs_a_target():
    assert codes('stage a:entry{arg value=1;}') == ["NO_TARGET"]


def test_all_diagnostics_reported_together():
    with pytest.raises(CompileError) as e:
        compile_program(parse('stage t:transform cuont{after zz;}stage o:output{after t;}'))
    assert {d.code for d in e.value.diagnostics} == {"UNKNOWN_OP", "UNKNOWN_DEP"}


def test_dead_stages_pruned():
    ir = compile_program(parse(
        'stage a:entry{arg value=1;}stage dead:transform identity{after a;}stage o:output{after a;}'))
    assert ir.pruned == ["dead"]
    assert [s.name for s in ir.program.stages] == ["a", "o"]


def test_levels_group_independent_stages():
    ir = compile_program(parse(workloads.W2))
    assert ir.levels[0] == ["a", "b"]
    assert ir.levels[1] == ["head", "total"]
    flat = [n for level in ir.levels for n in level]
    for s in ir.program.stages:
        for d in s.after:
            assert flat.index(d) < flat.index(s.name)


def test_capability_index_resolved():
    ir = compile_program(parse(workloads.W2))
    assert ir.cap_index == {"llm": 0, "news": 1, "out": 2, "sales": 3}


@pytest.mark.parametrize("name", sorted(workloads.SOURCES))
def test_binary_round_trip(name):
    ir = compile_program(parse(workloads.SOURCES[name]))
    back = load(emit(ir))
    assert back.program == ir.program and back.levels == ir.levels


def test_binary_is_deterministic():
    ir = compile_program(parse(workloads.W5))
    assert emit(ir) == emit(compile_program(parse(workloads.W5)))


def test_tampered_artifact_rejected():
    blob = bytearray(emit(compile_program(parse(workloads.W1))))
    blob[-1] ^= 1
    with pytest.raises(TdgError, match="digest"):
        load(bytes(blob))


def test_future_version_rejected():
    blob = bytearray(emit(compile_program(parse(workloads.W1))))
    blob[3] = 99
    with pytest.raises(TdgError, match="version"):
        load(bytes(blob))
