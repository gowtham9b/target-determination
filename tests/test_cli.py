import json

import workloads

from tdg.cli import main


def test_init_and_check(tmp_path, capsys):
    f = tmp_path / "g.tdg"
    assert main(["init", str(f)]) == 0
    assert main(["check", str(f)]) == 0
    assert "ok" in capsys.readouterr().out


def test_check_reports_proposals(tmp_path, capsys):
    f = tmp_path / "g.tdg"
    f.write_text("stage fetch:entry{arg value=1;}stage o:output{after fecth;}")
    assert main(["check", str(f)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report[0]["code"] == "UNKNOWN_DEP" and report[0]["proposals"]


def test_build_then_run_artifact(tmp_path, workdir, capsys):
    src = tmp_path / "w1.tdg"
    src.write_text(workloads.W1)
    world = tmp_path / "world.json"
    world.write_text(json.dumps(workloads.endpoints("W1")))
    art = tmp_path / "w1.tdgb"
    assert main(["build", str(src), "-o", str(art)]) == 0
    assert main(["run", str(art), "--world", str(world), "--workdir", workdir, "--par"]) == 0
    assert "target determined" in capsys.readouterr().out


def test_run_explain_accept_diff(tmp_path, workdir, capsys):
    src = tmp_path / "g.tdg"
    src.write_text('cap net n{allow "https://x.y/*";}'
                   'stage f:tool net.get{uses n;arg url="https://x.y/a";check status 200;viol propose;}'
                   'stage o:output{after f;}')
    world = tmp_path / "world.json"
    world.write_text(json.dumps({"https://x.y/a": {"status": 201, "body": "x"}}))
    trace = tmp_path / "t.json"
    assert main(["run", str(src), "--world", str(world), "--workdir", workdir, "--trace", str(trace)]) == 2
    main(["explain", str(trace), "f"])
    assert "suggested fix" in capsys.readouterr().out
    old = tmp_path / "old.tdg"
    old.write_text(src.read_text())
    assert main(["accept", str(src), str(trace), "0"]) == 0
    assert main(["run", str(src), "--world", str(world), "--workdir", workdir]) == 0
    capsys.readouterr()
    main(["diff", str(old), str(src)])
    assert "f.checks" in capsys.readouterr().out


def test_accept_refuses_authority_without_grant(tmp_path, workdir, capsys):
    src = tmp_path / "g.tdg"
    src.write_text('cap net n{allow "https://x.y/*";}stage f:tool net.get{uses n;arg url="https://z.y/a";fail propose;}'
                   'stage o:output{after f;}')
    trace = tmp_path / "t.json"
    assert main(["run", str(src), "--workdir", workdir, "--trace", str(trace)]) == 2
    report = json.loads(trace.read_text())
    assert report["proposals"] == [] and len(report["authority_requests"]) == 1
    before = src.read_text()
    report["proposals"] = report["authority_requests"]
    trace.write_text(json.dumps(report))
    assert main(["accept", str(src), str(trace), "0"]) == 3
    assert src.read_text() == before
    assert main(["accept", str(src), str(trace), "0", "--grant-authority"]) == 0
    assert "https://z.y/a" in src.read_text()


def test_fmt_is_canonical(tmp_path, capsys):
    f = tmp_path / "g.tdg"
    f.write_text("stage  x : entry { arg value = 1 ; }  stage y:output{after x;}")
    main(["fmt", str(f)])
    assert capsys.readouterr().out == "stage x:entry{arg value=1;}\nstage y:output{after x;}\n"
