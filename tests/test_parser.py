import pytest
import workloads

from tdg.core import Policy, Predicate, TdgError
from tdg.parser import parse, to_text


@pytest.mark.parametrize("name", sorted(workloads.SOURCES))
def test_workloads_round_trip(name):
    p = parse(workloads.SOURCES[name])
    assert parse(to_text(p)) == p


def test_whitespace_and_comments_are_insignificant():
    a = parse('stage x:entry{arg value=1;}stage y:output{after x;}')
    b = parse('/* c */ stage   x : entry {\n arg value = 1 ;\n}\n\n stage y:output{ after x ; }')
    assert a == b


def test_fields_are_typed():
    s = parse('cap net n{allow "https://a.b/*";}'
              'stage f:tool net.get{uses n;arg url="https://a.b/x";check status 200..299;'
              'check maxbytes 10;fail retry 2;viol propose;rand;}stage o:output{after f;}').stage("f")
    assert s.kind == "tool" and s.op == "net.get"
    assert s.checks == (Predicate("status", (200, 299)), Predicate("maxbytes", (10,)))
    assert s.on_fail == Policy("retry", 2) and s.on_violation == Policy("propose")
    assert s.stochastic


def test_single_status_is_a_degenerate_range():
    s = parse('stage f:transform identity{check status 200;}').stage("f")
    assert s.checks[0] == Predicate("status", (200, 200))


def test_capability_fields():
    p = parse('cap fs d{root "data";mode read;}cap model m{id "x";tokens 5;}cap shell s{allow "ls" "wc -l";}')
    assert p.cap("d").root == "data" and p.cap("d").mode == "read"
    assert p.cap("m").max_tokens == 5
    assert p.cap("s").allow == ("ls", "wc -l")


def test_arg_values_keep_types():
    s = parse('stage e:entry{arg a=1,b=2.5,c="x",d=true;}').stage("e")
    assert dict(s.args) == {"a": 1, "b": 2.5, "c": "x", "d": True}


def test_ordered_choice_prefers_maxbytes_over_max():
    s = parse('stage f:transform identity{check maxbytes 3;check max 3;}').stage("f")
    assert [c.op for c in s.checks] == ["maxbytes", "max"]


def test_parse_error_reports_offset():
    with pytest.raises(TdgError, match="offset"):
        parse('stage x:entry{arg value=1}')


def test_spans_cover_declarations():
    text = 'stage x:entry{arg value=1;} stage y:output{after x;}'
    p = parse(text)
    assert text[p.stage("y").span.start:p.stage("y").span.end].startswith("stage y")
