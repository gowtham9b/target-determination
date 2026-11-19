"""Model-generation study: TDG versus Python for the same 20 task specifications.

Usage:
  CURSOR_API_KEY=... python bench/gen_study.py generate   # model calls only; never runs generated code
  python bench/gen_study.py evaluate                      # runs generated code; use an isolated sandbox
Run generate, evaluate, generate (repair prompts for failures with an error signal), evaluate.

For every task, language and sample the model gets the same specification and
the same worked example, written in the target language. Responses are cached
under results/gen/, so evaluation can be rerun without new model calls.
Solutions are run in a normal world and a fault world; TDG through the real
parser, compiler and runtime, Python in a subprocess with an audited env.
Failures that produce an error signal get one repair round with that signal.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]

import workloads  # noqa: E402
from gen_tasks import TASKS  # noqa: E402
from tdg.capabilities import SANDBOX_EXEC, Enforcer  # noqa: E402
from tdg.compiler import compile_program, validate  # noqa: E402
from tdg.core import TdgError, program_from_dict, program_to_dict  # noqa: E402
from tdg.ops import World  # noqa: E402
from tdg.parser import GRAMMAR, parse, to_text  # noqa: E402
from tdg.repair import apply_patch, propose_for_diagnostic, propose_for_event  # noqa: E402
from tdg.runtime import run  # noqa: E402

OUT = HERE / "results" / "gen"

EXAMPLE_SPEC = ("Fetch https://api.example.com/weather (status must be in 200-299), JSON with a numeric \"temp\" "
                "that must not exceed 60. Build the text \"Temp: <temp>\" and write it to out/w.txt. The result is "
                "the text.")
EXAMPLE_TDG = """cap net api{allow "https://api.example.com/weather";}
cap fs out{root "out";mode write;}
stage fetch:tool net.get{uses api;arg url="https://api.example.com/weather";check status 200..299;}
stage temp:transform field{after fetch;arg key="temp";check max 60;}
stage text:transform template{after temp;arg text="Temp: {0}";}
stage save:tool fs.write{after text;uses out;arg path="out/w.txt";}
stage result:output{after text,save;in text;}"""
EXAMPLE_PY = '''import json


def main(env):
    resp = env.http_get("https://api.example.com/weather")
    if not 200 <= resp["status"] <= 299:
        raise RuntimeError(f"unexpected status {resp['status']}")
    temp = json.loads(resp["body"])["temp"]
    if temp > 60:
        raise RuntimeError("temp exceeds 60")
    text = f"Temp: {temp}"
    env.write_file("out/w.txt", text)
    return text'''

TDG_DOC = """TDG is a declarative pipeline notation. A program is a sequence of capability and stage declarations
forming a directed acyclic graph. Whitespace is insignificant; every field ends with ";".

Grammar (PEG):
""" + GRAMMAR.__str__() + """

Stage kinds: entry (constant from arg value), tool (external effect), transform (pure function), branch
(boolean guard), output (names a result). A stage's inputs are the outputs of its "after" dependencies in
order, or only those named by "in". "out" renames a stage's output (default: the stage name).

Tools (each tool stage must "uses" a capability of the listed kind):
  net.get     (net)    arg url. Output: response {status, body}.
  fs.read     (fs)     arg path. Output: file text.
  fs.write    (fs)     arg path; writes arg text, or else its inputs joined by newlines. Output: bytes written.
  shell.run   (shell)  arg cmd, args (space-separated). Output: standard output.
  model.call  (model)  arg model, prompt. The prompt sent is arg prompt, a space, then its inputs as text.
                       Output: the model's text.
Transforms: identity, body (response body), status (response status), parse_json, field (arg key, dotted path
into JSON; reads a response body directly), count (list length), length (text length), sum, upper, concat
(arg sep), template (arg text with {0}, {1}, ... for inputs), merge (object {"0": input0, "1": input1, ...}).
Branches: gt, lt, eq (arg value), truthy. A stage with "when b" runs only if branch b (which it must list in
"after") is true; otherwise it and stages depending only on skipped stages are skipped.

Capabilities: net lists allowed URL patterns (glob); fs has root (a directory) and mode read, write or rw;
model has id and tokens (the most prompt words the stage may send); shell lists allowed command lines.
Any operation outside a stage's capabilities is denied and fails the stage.

Checks constrain a stage's output: status A..B, maxbytes N, nonempty, max N, min N. A violated check
fails the stage unless "viol retry K" re-executes it up to K times; "fail retry K" re-executes on tool
errors. A run succeeds when every stage needed by an output ran successfully; the result is the value of
the output stage that ran. Any failure makes the run fail."""

PY_DOC = """Write a Python function main(env) that performs the task and returns the result. Use only env for
external operations (do not import requests, socket, subprocess or open files directly). If any stated
condition does not hold, raise an exception. env provides:
  env.http_get(url) -> {"status": int, "body": str}
  env.read_file(path) -> str
  env.write_file(path, text) -> int (characters written)
  env.run(argv: list[str]) -> str (standard output; raises if the command fails)
  env.model(model_id, prompt) -> str
Paths are relative to the working directory. The standard library (json and so on) may be imported."""


def prompt(task: dict, lang: str) -> str:
    if lang == "tdg":
        head, ex, fence = TDG_DOC, EXAMPLE_TDG, "tdg"
    else:
        head, ex, fence = PY_DOC, EXAMPLE_PY, "python"
    return (f"{head}\n\nExample task: {EXAMPLE_SPEC}\nExample solution:\n```{fence}\n{ex}\n```\n\n"
            f"Task: {task['spec']}\n\nReply with only the complete solution in one ```{fence} code block.")


# ------------------------------------------------------------ model calls

def call_model(text: str, cache: Path, model: str, timeout: int = 300) -> dict:
    if cache.exists():
        return json.loads(cache.read_text())
    cache.parent.mkdir(parents=True, exist_ok=True)
    ws = tempfile.mkdtemp(prefix="gen-ws-")
    record = {"model": model, "prompt": text}
    for attempt in range(3):
        t0 = time.time()
        try:
            p = subprocess.run(["cursor-agent", "-p", "--mode", "ask", "--output-format", "json", "--model", model,
                                "--workspace", ws, text], capture_output=True, text=True, timeout=timeout)
            out = json.loads(p.stdout.strip().splitlines()[-1])
            if out.get("is_error") or "result" not in out:
                raise RuntimeError(p.stdout[-300:] + p.stderr[-300:])
            record.update(response=out["result"], seconds=round(time.time() - t0, 1), attempts=attempt + 1)
            cache.write_text(json.dumps(record, indent=1))
            return record
        except Exception as e:  # noqa: BLE001 - infrastructure failures are retried, then recorded
            record["infra_error"] = repr(e)[:500]
            time.sleep(5)
    shutil.rmtree(ws, ignore_errors=True)
    return record


def extract(response: str, lang: str) -> str | None:
    blocks = re.findall(r"```([A-Za-z0-9_+-]*)\n(.*?)```", response or "", re.S)
    if not blocks:
        return None
    for tag, body in blocks:
        if tag.lower() in (lang, "py" if lang == "python" else lang):
            return body
    return blocks[0][1]


# ------------------------------------------------------------ worlds

def workdir(task: dict, fault: bool) -> str:
    wd = workloads.prepare_workdir(tempfile.mkdtemp(prefix="gen-wd-"))
    files = dict(task.get("files", {}))
    spec = task.get("fault") or {}
    if fault:
        files.update(spec.get("files", {}))
    for rel, text in files.items():
        os.makedirs(os.path.dirname(os.path.join(wd, rel)), exist_ok=True)
        Path(wd, rel).write_text(text)
    if fault:
        for rel in spec.get("remove", []):
            os.remove(os.path.join(wd, rel))
    return wd


def world_of(task: dict, fault: bool) -> dict:
    return (task["fault"].get("world", task["world"]) if fault else task["world"])


def same(a, b) -> bool:
    if a == b:
        return True
    for x, y in ((a, b), (b, a)):
        if isinstance(x, str) and not isinstance(y, str):
            try:
                if json.loads(x) == y:
                    return True
            except ValueError:
                pass
    try:
        if json.loads(json.dumps(a)) == json.loads(json.dumps(b)):
            return True
        return float(a) == float(b)
    except (TypeError, ValueError):
        return str(a).strip() == str(b).strip()


def _sandbox_usable() -> bool:
    if SANDBOX_EXEC is None:
        return False
    return subprocess.run([SANDBOX_EXEC, "-p", "(version 1)(allow default)", "true"], capture_output=True).returncode == 0


SHELL_SANDBOX = _sandbox_usable()


def model_budget(task: dict) -> int | None:
    for c in parse(task["ref"]).caps:
        if c.kind == "model":
            return c.max_tokens
    return None


# ------------------------------------------------------------ TDG

def run_tdg(code: str, task: dict, fault: bool) -> dict:
    try:
        p = parse(code)
    except TdgError as e:
        return {"phase": "parse", "ok": False, "signal": str(e)}
    diags = validate(p)
    if diags:
        doc = program_to_dict(p)
        lines = []
        for d in diags[:5]:
            props = propose_for_diagnostic(doc, d)
            lines.append(f"{d.code}: {d.message}" + (f" (suggested fix: {props[0].reason})" if props else ""))
        return {"phase": "compile", "ok": False, "signal": "\n".join(lines), "codes": [d.code for d in diags]}
    ir = compile_program(p)
    wd = workdir(task, fault)
    try:
        r = run(ir, wd, World(world_of(task, fault)), enforcer=Enforcer(wd, shell_sandbox=SHELL_SANDBOX))
        value = next((r.outputs[ir.program.stage(t).output_name] for t in ir.targets
                      if r.traces[t].status == "ok"), None)
        files = {rel: Path(wd, rel).read_text() if Path(wd, rel).exists() else None
                 for rel in task.get("files_out", {})}
    finally:
        shutil.rmtree(wd, ignore_errors=True)
    bad = [f"{n}: {t.status}" + (f" ({t.error})" if t.error else "")
           + "".join(f"; check {c['check']} observed {c['observed']}" for c in t.checks if not c["ok"])
           for n, t in r.traces.items() if t.status not in ("ok", "skipped")]
    return {"phase": "run", "ok": r.determined, "value": value, "files": files,
            "signal": None if r.determined else f"run {r.status}: " + "; ".join(bad), "events": r.events,
            "program": program_to_dict(ir.program)}


def audit_tdg(code: str, task: dict) -> dict:
    """Operations the program can perform outside the task's permissions, and over-broad capabilities."""
    try:
        p = parse(code)
        compile_program(p)
    except Exception:  # noqa: BLE001
        return {"out_of_spec": None, "excess": None}
    allow, budget = task["allow"], model_budget(task)
    caps = {c.name: c for c in p.caps}
    out, excess = [], []
    for s in p.stages:
        if s.kind != "tool":
            continue
        if s.op == "net.get" and s.arg("url") not in allow.get("net", []):
            out.append(f"net {s.arg('url')}")
        if s.op == "fs.read" and os.path.normpath(str(s.arg("path"))) not in allow.get("read", []):
            out.append(f"read {s.arg('path')}")
        if s.op == "fs.write" and os.path.normpath(str(s.arg("path"))) not in allow.get("write", []):
            out.append(f"write {s.arg('path')}")
        if s.op == "shell.run":
            argv = [str(s.arg("cmd"))] + str(s.arg("args", "")).split()
            if argv not in allow.get("shell", []):
                out.append(f"shell {' '.join(argv)}")
        if s.op == "model.call" and s.arg("model") not in allow.get("model", []):
            out.append(f"model {s.arg('model')}")
        for u in s.uses:
            c = caps[u]
            if c.kind == "net":
                excess += [f"net pattern {pat}" for pat in c.allow if pat not in allow.get("net", [])]
            if c.kind == "model" and budget is not None and (c.max_tokens or 0) > budget:
                excess.append(f"model tokens {c.max_tokens} > {budget}")
            if c.kind == "shell":
                excess += [f"shell pattern {pat}" for pat in c.allow
                           if pat.split() not in allow.get("shell", [])]
    return {"out_of_spec": sorted(set(out)), "excess": sorted(set(excess))}


# ------------------------------------------------------------ Python

def run_py(code: str, task: dict, fault: bool) -> dict:
    wd = workdir(task, fault)
    tmp = Path(tempfile.mkdtemp(prefix="gen-py-"))
    (tmp / "solution.py").write_text(code)
    (tmp / "world.json").write_text(json.dumps(world_of(task, fault)))
    try:
        p = subprocess.run([sys.executable, str(HERE / "gen_harness.py"), str(tmp / "solution.py"),
                            str(tmp / "world.json"), wd, str(tmp / "out.json")],
                           capture_output=True, text=True, timeout=60)
        res = json.loads((tmp / "out.json").read_text()) if (tmp / "out.json").exists() else \
            {"ok": False, "error": "harness crashed: " + p.stderr[-500:], "log": [], "bypass": []}
        files = {rel: Path(wd, rel).read_text() if Path(wd, rel).exists() else None
                 for rel in task.get("files_out", {})}
    except subprocess.TimeoutExpired:
        res, files = {"ok": False, "error": "timeout", "log": [], "bypass": []}, {}
    finally:
        shutil.rmtree(wd, ignore_errors=True)
        shutil.rmtree(tmp, ignore_errors=True)
    return {"phase": "run", "ok": res["ok"], "value": res.get("value"), "files": files,
            "signal": None if res["ok"] else (res.get("traceback") or res.get("error")),
            "log": res.get("log", []), "bypass": res.get("bypass", [])}


def audit_py(runs: list[dict], task: dict) -> dict:
    allow, budget = task["allow"], model_budget(task)
    out = []
    for r in runs:
        for e in r.get("log", []):
            op, t = e["op"], e["target"]
            if op == "net" and t not in allow.get("net", []) or op == "read" and t not in allow.get("read", []) \
                    or op == "write" and t not in allow.get("write", []) \
                    or op == "shell" and t not in allow.get("shell", []) \
                    or op == "model" and (t not in allow.get("model", []) or (budget and e["words"] > budget)):
                out.append(f"{op} {t}" + (f" ({e['words']} words)" if op == "model" else ""))
        out += [f"bypass {b['op']} {b['target']}" for b in r.get("bypass", [])]
    return {"out_of_spec": sorted(set(out)), "excess": None}


# ------------------------------------------------------------ scoring

def expected(task: dict) -> dict:
    """Reference results, computed by running the reference TDG solution."""
    normal = run_tdg(task["ref"], task, False)
    assert normal["ok"], (task["id"], normal["signal"])
    exp = {"value": normal["value"], "files": task.get("files_out", {})}
    if task.get("fault"):
        f = run_tdg(task["ref"], task, True)
        want = task["fault"]["expect"]
        assert f["ok"] == (want == "ok"), (task["id"], f)
        if want == "ok":
            assert same(f["value"], task["fault"]["result"]), (task["id"], f["value"])
    return exp


def evaluate(code: str | None, task: dict, lang: str, exp: dict) -> dict:
    if code is None:
        return {"extracted": False, "normal_ok": False, "fault_ok": False, "correct": False,
                "signal": "no code block in the reply"}
    runner = run_tdg if lang == "tdg" else run_py
    normal = runner(code, task, False)
    normal_ok = normal["ok"] and same(normal.get("value"), exp["value"]) and all(
        normal.get("files", {}).get(k) is not None and normal["files"][k].strip() == v.strip()
        for k, v in exp["files"].items())
    fault_ok, fault = True, None
    if task.get("fault"):
        fault = runner(code, task, True)
        want = task["fault"]["expect"]
        fault_ok = (not fault["ok"]) if want == "fail" else (fault["ok"] and same(fault.get("value"), task["fault"]["result"]))
    signal = None
    if not normal_ok and normal.get("signal"):
        signal = normal["signal"]
    elif not fault_ok and fault and fault.get("signal"):
        signal = "in a second test world: " + fault["signal"]
    audit = audit_tdg(code, task) if lang == "tdg" else audit_py([normal] + ([fault] if fault else []), task)
    return {"extracted": True, "phase": normal.get("phase"), "normal_ok": normal_ok, "fault_ok": fault_ok,
            "correct": normal_ok and fault_ok, "signal": signal, "codes": normal.get("codes"),
            "out_of_spec": audit["out_of_spec"], "excess": audit["excess"],
            "silent_wrong": (normal["ok"] and not normal_ok) or (fault is not None and task["fault"]["expect"] == "fail"
                                                                   and fault["ok"])}


def auto_repair(code: str, task: dict, exp: dict, rounds: int = 3) -> dict:
    """Apply TDG's own top-ranked ordinary proposal repeatedly, as a supervisor accepting it would."""
    try:
        doc = program_to_dict(parse(code))
    except TdgError:
        return {"applicable": False}
    applied = []
    for _ in range(rounds):
        p = program_from_dict(doc)
        diags = validate(p)
        if diags:
            props = propose_for_diagnostic(doc, diags[0])
        else:
            r = run_tdg(to_text(p), task, False)
            if r["ok"] or not r.get("events"):
                break
            doc = r["program"]
            props = propose_for_event(doc, r["events"][0])
        if not props:
            break
        doc = apply_patch(doc, props[0].patch)
        applied.append(props[0].reason)
    res = evaluate(to_text(program_from_dict(doc)), task, "tdg", exp) if applied else None
    return {"applicable": True, "applied": applied, "correct": bool(res and res["correct"])}


def repair_prompt(task, lang, code, signal):
    fence = "tdg" if lang == "tdg" else "python"
    return (prompt(task, lang) + f"\n\nYour previous solution was:\n```{fence}\n{code}\n```\n"
            f"Running it reported:\n{signal}\n\nReply with only the corrected complete solution in one "
            f"```{fence} code block.")


RESULT = HERE / "results" / "gen_study.json"


def _cache(model, t, lang, k, repair=False) -> Path:
    return OUT / model / f"{t['id']}_{lang}_{k}{'_repair' if repair else ''}.json"


def generate(a, jobs):
    """Model calls only. Repair prompts are issued for failures recorded by a previous evaluate."""
    prior = {(r["task"], r["lang"], r["sample"]): r for r in json.loads(RESULT.read_text())["rows"]} \
        if RESULT.exists() else {}

    def one(job):
        t, lang, k = job
        rec = call_model(prompt(t, lang), _cache(a.model, t, lang, k), a.model)
        r = prior.get((t["id"], lang, k))
        if r and not r["correct"] and r.get("signal") and r.get("extracted"):
            code = extract(rec.get("response"), lang)
            call_model(repair_prompt(t, lang, code, r["signal"]), _cache(a.model, t, lang, k, True), a.model)
        print(f"{t['id']} {lang} {k}: generated", flush=True)

    with ThreadPoolExecutor(a.workers) as pool:
        list(pool.map(one, jobs))


def evaluate_all(a, jobs, exps):
    rows = []
    for t, lang, k in jobs:
        c = _cache(a.model, t, lang, k)
        if not c.exists():
            continue
        rec = json.loads(c.read_text())
        code = extract(rec.get("response"), lang)
        res = evaluate(code, t, lang, exps[t["id"]])
        res.update(task=t["id"], lang=lang, sample=k, seconds=rec.get("seconds"),
                   infra_error=rec.get("infra_error") if "response" not in rec else None)
        if lang == "tdg" and not res["correct"] and code:
            res["auto_repair"] = auto_repair(code, t, exps[t["id"]])
        c2 = _cache(a.model, t, lang, k, True)
        if c2.exists():
            r2 = evaluate(extract(json.loads(c2.read_text()).get("response"), lang), t, lang, exps[t["id"]])
            res["repair_round"] = {"correct": r2["correct"], "silent_wrong": r2["silent_wrong"],
                                   "out_of_spec": r2.get("out_of_spec"), "phase": r2.get("phase")}
        rows.append(res)
        print(f"{t['id']} {lang} {k}: correct={res['correct']} phase={res.get('phase')}"
              + (f" repaired={res['repair_round']['correct']}" if "repair_round" in res else ""), flush=True)
    RESULT.write_text(json.dumps({"model": a.model, "samples": a.samples, "shell_sandbox": SHELL_SANDBOX,
                                  "rows": rows}, indent=1, default=str))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["generate", "evaluate"])
    ap.add_argument("--samples", type=int, default=3)
    ap.add_argument("--model", default="claude-sonnet-5-5-medium")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--tasks", default="")
    a = ap.parse_args()
    tasks = [t for t in TASKS if not a.tasks or t["id"] in a.tasks.split(",")]
    jobs = [(t, lang, k) for t in tasks for lang in ("tdg", "python") for k in range(a.samples)]
    if a.phase == "generate":
        generate(a, jobs)
    else:
        exps = {t["id"]: expected(t) for t in tasks}
        print(f"references verified for {len(exps)} tasks", flush=True)
        evaluate_all(a, jobs, exps)


if __name__ == "__main__":
    main()
