"""Benchmarks for the TDG prototype. Writes JSON results to bench/results/.

Usage: python bench/run_bench.py [--quick]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import statistics
import string
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]

import workloads  # noqa: E402
from tdg.capabilities import CapabilityDenied, Enforcer, Gate, Token  # noqa: E402
from tdg.compiler import CompileError, compile_program, emit, load, validate  # noqa: E402
from tdg.core import Capability, Policy, Predicate, program_from_dict, program_to_dict  # noqa: E402
from tdg.ops import World  # noqa: E402
from tdg.parser import parse, to_text  # noqa: E402
from tdg.repair import apply_patch, propose_for_diagnostic, propose_for_event  # noqa: E402
from tdg.runtime import run  # noqa: E402

RESULTS = HERE / "results"


def timed(fn, min_reps=5, min_seconds=0.3):
    """Median wall time of fn() in milliseconds."""
    samples, start = [], time.perf_counter()
    while len(samples) < min_reps or time.perf_counter() - start < min_seconds:
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1e6)
        if len(samples) >= 10_000:
            break
    return statistics.median(samples)


# ------------------------------------------------------------ lexical demand

def lexical():
    import tiktoken
    encs = {name: tiktoken.get_encoding(name) for name in ("o200k_base", "cl100k_base")}
    rows = []
    for name, src in workloads.SOURCES.items():
        texts = {
            "tdg": src,
            "script": (HERE / "baselines" / f"{name.lower()}_script.py").read_text(),
            "airflow": (HERE / "baselines" / f"{name.lower()}_airflow.py").read_text(),
        }
        row = {"workload": name, "stages": len(parse(src).stages)}
        for enc_name, enc in encs.items():
            for form, text in texts.items():
                row[f"{form}_{enc_name}"] = len(enc.encode(text))
        row.update({f"{form}_chars": len(t) for form, t in texts.items()})
        rows.append(row)
    return rows


# ------------------------------------------------------------ parse/compile scaling

def generated(n: int) -> str:
    """A layered graph of n stages (width 4) ending in one output stage."""
    parts = ['cap net api{allow "https://api.example.com/*";}']
    names = []
    for i in range(n - 1):
        deps = [names[i - 4]] if i >= 4 else []
        after = f"after {','.join(deps)};" if deps else ""
        if i % 4 == 0:
            parts.append(f'stage s{i}:tool net.get{{{after}uses api;arg url="https://api.example.com/r{i}";'
                         f'check status 200..299;viol propose;}}')
        else:
            parts.append(f"stage s{i}:transform identity{{{after}check maxbytes 4096;viol retry 1;}}")
        names.append(f"s{i}")
    tail = names[-4:] if names else []
    after = f"after {','.join(tail)};" if tail else ""
    parts.append(f"stage out:output{{{after}}}")
    return "\n".join(parts) + "\n"


def scaling(sizes):
    rows = []
    for n in sizes:
        text = generated(n)
        program = parse(text)
        ir = compile_program(program)
        blob = emit(ir)
        rows.append({
            "stages": n,
            "text_bytes": len(text.encode()),
            "artifact_bytes": len(blob),
            "levels": len(ir.levels),
            "parse_ms": timed(lambda: parse(text)),
            "compile_ms": timed(lambda: compile_program(program)),
            "emit_ms": timed(lambda: emit(ir)),
            "load_ms": timed(lambda: load(blob)),
            "print_ms": timed(lambda: to_text(program)),
        })
        print(f"  scaling n={n}: parse {rows[-1]['parse_ms']:.3f} ms", flush=True)
    return rows


# ------------------------------------------------------------ scheduling

def wide(width: int, depth: int) -> tuple[str, dict]:
    parts = ['cap net api{allow "https://api.example.com/*";}']
    endpoints = {}
    for d in range(depth):
        for w in range(width):
            url = f"https://api.example.com/l{d}/{w}"
            endpoints[url] = {"status": 200, "body": f'{{"v":{d * width + w}}}'}
            after = f"after l{d - 1}_{w};" if d else ""
            parts.append(f'stage l{d}_{w}:tool net.get{{{after}uses api;arg url="{url}";check status 200..299;}}')
    last = ",".join(f"l{depth - 1}_{w}" for w in range(width))
    parts.append(f"stage out:output{{after {last};}}")
    return "\n".join(parts), endpoints


def scheduling(latency_s=0.02, reps=7):
    cases = [(n, workloads.SOURCES[n], workloads.endpoints(n)) for n in ("W2", "W5")]
    src, eps = wide(8, 3)
    cases.append(("wide8x3", src, eps))
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        wd = workloads.prepare_workdir(tmp)
        for name, src, eps in cases:
            ir = compile_program(parse(src))
            row = {"workload": name, "stages": len(ir.program.stages), "levels": len(ir.levels),
                   "max_width": max(len(lv) for lv in ir.levels), "latency_ms": latency_s * 1000}
            for mode in ("seq", "par"):
                row[f"{mode}_ms"] = timed(
                    lambda: run(ir, wd, World(eps, latency_s=latency_s), parallel=mode == "par"),
                    min_reps=reps, min_seconds=0)
            row["speedup"] = row["seq_ms"] / row["par_ms"]
            rows.append(row)
        overhead = {}
        for name, src in workloads.SOURCES.items():
            ir = compile_program(parse(src))
            eps = workloads.endpoints(name)
            overhead[name] = {
                "stages": len(ir.program.stages),
                "seq_ms": timed(lambda: run(ir, wd, World(eps))),
                "par_ms": timed(lambda: run(ir, wd, World(eps), parallel=True)),
            }
    return {"latency_runs": rows, "zero_latency": overhead}


# ------------------------------------------------------------ capability trials

FS_R = Capability("data", "fs", root="data", mode="read")
FS_W = Capability("out", "fs", root="out", mode="write")
NET = Capability("api", "net", allow=("https://api.example.com/v1/*",))
SH = Capability("sh", "shell", allow=("wc -l data/*.csv",))
MODEL = Capability("llm", "model", model_id="mock-1", max_tokens=50)


def _word(rng, k=6):
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(k))


def capability_trials(wd: str, per_category=25, seed=0, shell_matching="argv"):
    rng = random.Random(seed)
    for i in range(per_category):
        with open(os.path.join(wd, "private", f"k{i}.csv"), "w") as f:
            f.write("secret,1\n")
        with open(os.path.join(wd, "data", f"f{i}.csv"), "w") as f:
            f.write("a,b\n1,2\n")
    world = World({f"https://api.example.com/v1/{_word(random.Random(i))}": {"status": 200, "body": "ok"}
                   for i in range(per_category)})

    def fresh(stage, *caps):
        e = Enforcer(wd, shell_matching=shell_matching)
        toks = [e.issue(stage, c) for c in caps]
        return e, toks, Gate(e, stage, toks, world)

    attacks, benign = [], []

    def attempt(bucket, category, fn, target):
        try:
            fn()
            bucket.append({"category": category, "target": target, "denied": False})
        except CapabilityDenied as e:
            bucket.append({"category": category, "target": target, "denied": True, "reason": e.reason})
        except Exception as e:  # noqa: BLE001
            bucket.append({"category": category, "target": target, "denied": False, "error": repr(e)})

    for i in range(per_category):
        # 1. path traversal and absolute paths
        p = rng.choice([f"data/../private/k{i}.csv", f"data/./../private/k{i}.csv",
                        os.path.join(wd, "private", f"k{i}.csv"), f"private/k{i}.csv", "/etc/hosts"])
        _, _, g = fresh("s", FS_R)
        attempt(attacks, "fs_traversal", lambda: g.read_file(p), p)
        attempt(benign, "fs_read", lambda: g.read_file(f"data/f{i}.csv"), f"data/f{i}.csv")
        # 2. symlink escape
        link = os.path.join(wd, "data", f"link{i}.csv")
        if not os.path.lexists(link):
            os.symlink(os.path.join(wd, "private", f"k{i}.csv"), link)
        _, _, g = fresh("s", FS_R)
        attempt(attacks, "fs_symlink", lambda: g.read_file(f"data/link{i}.csv"), f"data/link{i}.csv")
        attempt(benign, "fs_read_nested", lambda: g.read_file("data/events.csv"), "data/events.csv")
        # 3. write with read-only token
        _, _, g = fresh("s", FS_R)
        attempt(attacks, "fs_write_readonly", lambda: g.write_file(f"data/w{i}.txt", "x"), f"data/w{i}.txt")
        _, _, gw = fresh("s", FS_W)
        attempt(benign, "fs_write", lambda: gw.write_file(f"out/w{i}.txt", "x"), f"out/w{i}.txt")
        # 4. host not allowed
        host = rng.choice([f"{_word(rng)}.com", "api.example.com.evil.net", "example.com",
                           "api-example.com", "169.254.169.254"])
        url = f"https://{host}/v1/{_word(rng)}"
        _, _, g = fresh("s", NET)
        attempt(attacks, "net_host", lambda: g.http_get(url), url)
        good = f"https://api.example.com/v1/{_word(random.Random(i))}"
        attempt(benign, "net_get", lambda: g.http_get(good), good)
        # 5. scheme, port, path, credentials
        url = rng.choice([f"http://api.example.com/v1/{_word(rng)}", f"https://api.example.com:8443/v1/{_word(rng)}",
                          f"https://api.example.com/v2/{_word(rng)}", f"https://api.example.com/{_word(rng)}",
                          f"https://user@evil.com/v1/{_word(rng)}"])
        _, _, g = fresh("s", NET)
        attempt(attacks, "net_scope", lambda: g.http_get(url), url)
        attempt(benign, "net_get_repeat", lambda: g.http_get(good), good)
        # 6. command not allowed
        argv = rng.choice([["cat", "data/events.csv"], ["rm", f"data/f{i}.csv"], ["python3", "-c", "print(1)"],
                           ["curl", "https://evil.com"], ["sh", "-c", "wc -l data/events.csv"]])
        _, _, g = fresh("s", SH)
        attempt(attacks, "shell_command", lambda: g.run(argv), " ".join(argv))
        attempt(benign, "shell_run", lambda: g.run(["wc", "-l", f"data/f{i}.csv"]), f"wc -l data/f{i}.csv")
        # 7. argument smuggling under an allowed command pattern
        argv = rng.choice([["wc", "-l", f"data/../private/k{i}.csv"], ["wc", "-l", f"data/f{i}.csv", f"private/k{i}.csv"],
                           ["wc", "-l", f"data/f{i}.csv;cat", "x.csv"], ["wc", "-l", f"data/link{i}.csv"],
                           ["wc", "-l", f"private/k{i}.csv"], ["wc", "-l", os.path.join(wd, "private", f"k{i}.csv")]])
        _, _, g = fresh("s", SH)
        attempt(attacks, "shell_args", lambda: g.run(argv), " ".join(argv))
        attempt(benign, "shell_run_repeat", lambda: g.run(["wc", "-l", "data/events.csv"]), "wc -l data/events.csv")
        # 8. token misuse: sibling reuse, forgery, widening, model scope
        kind = i % 5
        e, toks, g = fresh("a", FS_R, MODEL)
        if kind == 0:
            attempt(attacks, "token_misuse", lambda: e.check_fs("b", toks[0], "data/events.csv", "read"), "sibling reuse")
        elif kind == 1:
            attempt(attacks, "token_misuse", lambda: e.check_fs("a", Token(10_000 + i, "a", FS_R), "data/events.csv", "read"), "forged token")
        elif kind == 2:
            attempt(attacks, "token_misuse", lambda: e.attenuate(toks[0], mode="rw"), "widen mode")
        elif kind == 3:
            attempt(attacks, "token_misuse", lambda: g.model("other-model", "hi", False), "model id")
        else:
            attempt(attacks, "token_misuse", lambda: g.model("mock-1", " ".join(["w"] * 60), False), "token ceiling")
        attempt(benign, "token_use", lambda: g.model("mock-1", "summarize this", False), "model within ceiling")

    def summarize(bucket):
        cats = {}
        for t in bucket:
            c = cats.setdefault(t["category"], {"n": 0, "denied": 0})
            c["n"] += 1
            c["denied"] += t["denied"]
        return cats

    bypasses = [t for t in attacks if not t["denied"]]
    false_denials = [t for t in benign if t["denied"]]
    return {"attacks": summarize(attacks), "benign": summarize(benign),
            "n_attacks": len(attacks), "n_benign": len(benign),
            "bypasses": bypasses, "false_denials": false_denials}


def check_latency(wd: str):
    e = Enforcer(wd)
    tf, tn, ts, tm = (e.issue("s", c) for c in (FS_R, NET, SH, Capability("m", "model", model_id="mock-1", max_tokens=10**12)))
    return {
        "fs_us": timed(lambda: e.check_fs("s", tf, "data/events.csv", "read")) * 1000,
        "net_us": timed(lambda: e.check_net("s", tn, "https://api.example.com/v1/x")) * 1000,
        "shell_us": timed(lambda: e.check_shell("s", ts, ["wc", "-l", "data/events.csv"])) * 1000,
        "model_us": timed(lambda: e.check_model("s", tm, "mock-1", 1)) * 1000,
    }


# ------------------------------------------------------------ repair trials

def typo(word: str, rng: random.Random, avoid: set[str]) -> str | None:
    for _ in range(50):
        w = list(word)
        op = rng.choice(["swap", "delete", "double", "replace"])
        letters = [i for i, ch in enumerate(w) if ch.isalpha()]
        if not letters:
            return None
        i = rng.choice(letters)
        if op == "swap" and i + 1 < len(w) and w[i + 1].isalpha() and w[i] != w[i + 1]:
            w[i], w[i + 1] = w[i + 1], w[i]
        elif op == "delete" and len(w) >= 3:
            del w[i]
        elif op == "double":
            w.insert(i, w[i])
        elif op == "replace":
            w[i] = rng.choice([c for c in string.ascii_lowercase if c != w[i]])
        else:
            continue
        new = "".join(w)
        if new != word and new not in avoid and new[0].isalpha():
            return new
    return None


def _set_stage(doc, name, **fields):
    for s in doc["stages"]:
        if s["name"] == name:
            s.update(fields)
            return s
    raise KeyError(name)


def make_fault(category: str, rng: random.Random):
    """Return (workload, faulted doc, endpoints, original doc) or None if not applicable."""
    name = rng.choice(sorted(workloads.SOURCES))
    original = program_to_dict(parse(workloads.SOURCES[name]))
    doc = json.loads(json.dumps(original))
    eps = json.loads(json.dumps(workloads.endpoints(name)))
    stages = doc["stages"]
    names = {s["name"] for s in stages}
    net = [s for s in stages if s.get("op") == "net.get"]

    if category == "dep_typo":
        cands = [s for s in stages if s.get("after")]
        s = rng.choice(cands)
        j = rng.randrange(len(s["after"]))
        t = typo(s["after"][j], rng, names)
        if t is None:
            return None
        s["after"][j] = t
    elif category == "input_typo":
        cands = [s for s in stages if s.get("inputs")]
        if not cands:
            return None
        s = rng.choice(cands)
        j = rng.randrange(len(s["inputs"]))
        t = typo(s["inputs"][j], rng, names)
        if t is None:
            return None
        s["inputs"][j] = t
    elif category == "op_typo":
        cands = [s for s in stages if s.get("op")]
        s = rng.choice(cands)
        t = typo(s["op"], rng, set())
        if t is None:
            return None
        s["op"] = t
    elif category == "cap_typo":
        cands = [s for s in stages if s.get("uses")]
        if not cands:
            return None
        s = rng.choice(cands)
        t = typo(s["uses"][0], rng, {c["name"] for c in doc["caps"]})
        if t is None:
            return None
        s["uses"][0] = t
    elif category == "status_strict":
        if not net:
            return None
        s = rng.choice(net)
        s["checks"] = [c if c["op"] != "status" else {"op": "status", "args": [200, 200]} for c in s["checks"]]
        url = s["args"]["url"]
        spec = eps[url][-1] if isinstance(eps[url], list) else eps[url]
        eps[url] = {"status": rng.choice([201, 202, 204]), "body": spec["body"]}
    elif category == "transient_5xx":
        if not net:
            return None
        s = rng.choice(net)
        s["on_violation"] = {"action": "propose", "count": 0}
        url = s["args"]["url"]
        spec = eps[url][-1] if isinstance(eps[url], list) else eps[url]
        k = rng.randint(1, 4)
        eps[url] = [{"status": rng.choice([500, 502, 503]), "body": ""}] * k + [spec]
    elif category == "field_key_typo":
        cands = [s for s in stages if s.get("op") == "field"]
        if not cands:
            return None
        s = rng.choice(cands)
        t = typo(s["args"]["key"], rng, set())
        if t is None:
            return None
        s["args"]["key"] = t
    elif category == "bound_tight":
        r = run(compile_program(program_from_dict(original)), _WD, World(eps))
        cands = []
        for s in stages:
            for k, c in enumerate(s.get("checks", [])):
                obs = next((x["observed"] for x in r.traces[s["name"]].checks if x["check"] == Predicate(c["op"], tuple(c["args"])).text()), None)
                if c["op"] in ("maxbytes", "max") and isinstance(obs, (int, float)) and obs > 1:
                    cands.append((s, k, c["op"], max(0, int(obs) // 2)))
                if c["op"] == "min" and isinstance(obs, (int, float)):
                    cands.append((s, k, "min", int(obs) + 1 + rng.randint(0, 5)))
        if not cands:
            return None
        s, k, op, bound = rng.choice(cands)
        s["checks"][k] = {"op": op, "args": [bound]}
        if s.get("on_violation", {}).get("action") == "retry":
            s["on_violation"] = {"action": "propose", "count": 0}
    elif category == "permanent_404":
        if not net:
            return None
        s = rng.choice(net)
        eps[s["args"]["url"]] = {"status": 404, "body": ""}
    elif category == "url_host_typo":
        if not net:
            return None
        s = rng.choice(net)
        url = s["args"]["url"]
        host = url.split("/")[2]
        t = typo(host.split(".")[0], rng, set())
        if t is None:
            return None
        s["args"]["url"] = url.replace(host, t + host[len(host.split(".")[0]):], 1)
    else:
        raise ValueError(category)
    return name, doc, eps, original


_WD = None


def evaluate(doc, eps):
    """Return (determined, proposals) for one program/world."""
    p = program_from_dict(doc)
    diags = validate(p)
    if diags:
        return False, propose_for_diagnostic(doc, diags[0]), "compile"
    ir = compile_program(p)
    r = run(ir, _WD, World(eps))
    if r.determined:
        return True, [], "none"
    if not r.events:
        return False, [], "blocked"
    return False, propose_for_event(program_to_dict(ir.program), r.events[0]), r.events[0]["type"]


def repair_trials(per_category=25, seed=1):
    rng = random.Random(seed)
    positive = ["dep_typo", "input_typo", "op_typo", "cap_typo", "status_strict",
                "transient_5xx", "field_key_typo", "bound_tight"]
    negative = ["permanent_404", "url_host_typo"]
    trials = []
    for category in positive + negative:
        made = 0
        while made < per_category:
            fault = make_fault(category, rng)
            if fault is None:
                continue
            name, doc, eps, original = fault
            if doc == original and category not in ("transient_5xx", "status_strict", "permanent_404"):
                continue
            determined, proposals, detected_by = evaluate(doc, eps)
            changed = [(a["name"], {k: (a.get(k), b.get(k)) for k in a.keys() | b.keys() if a.get(k) != b.get(k)})
                       for a, b in zip(original["stages"], doc["stages"]) if a != b]
            row = {"category": category, "workload": name, "changed": changed, "detected": not determined,
                   "detected_by": detected_by, "n_proposals": len(proposals),
                   "top1_kind": proposals[0].kind if proposals else None}
            resolved = []
            for prop in proposals[:3]:
                try:
                    patched = apply_patch(doc, prop.patch)
                    ok = evaluate(patched, eps)[0]
                except Exception:  # noqa: BLE001
                    ok, patched = False, None
                resolved.append((ok, patched, prop))
            if category == "transient_5xx":
                row["failures_before_success"] = next(
                    len(v) - 1 for v in eps.values() if isinstance(v, list) and v[0]["status"] >= 500)
            row["top1_resolves"] = bool(resolved) and resolved[0][0]
            row["top3_resolves"] = any(ok for ok, _, _ in resolved)
            if category == "transient_5xx":
                row["top1_intended"] = bool(resolved) and resolved[0][2].kind == "retry" and resolved[0][0]
            elif category == "status_strict":
                row["top1_intended"] = bool(resolved) and resolved[0][0] and resolved[0][2].kind == "relax"
            else:
                row["top1_intended"] = bool(resolved) and resolved[0][1] == original
            trials.append(row)
            made += 1
    summary = {}
    for t in trials:
        c = summary.setdefault(t["category"], {"n": 0, "detected": 0, "proposed": 0, "top1_resolves": 0,
                                               "top3_resolves": 0, "top1_intended": 0, "top1_authority": 0})
        c["n"] += 1
        c["detected"] += t["detected"]
        c["proposed"] += t["n_proposals"] > 0
        c["top1_resolves"] += t["top1_resolves"]
        c["top3_resolves"] += t["top3_resolves"]
        c["top1_intended"] += t["top1_intended"]
        c["top1_authority"] += t["top1_kind"] == "authority"
    return {"summary": summary, "trials": trials}


# ------------------------------------------------------------ determinism

def determinism(runs_per_workload=2000):
    out = {}
    for name, src in workloads.SOURCES.items():
        ir = compile_program(parse(src))
        eps = workloads.endpoints(name)
        digests = {run(ir, _WD, World(eps), parallel=bool(k % 2)).final_digest for k in range(runs_per_workload)}
        out[name] = {"runs": runs_per_workload, "distinct_digests": len(digests)}
    p = parse(workloads.W2)
    stoch = replace(p, stages=tuple(replace(s, stochastic=True) if s.name == "summary" else s for s in p.stages))
    ir = compile_program(stoch)
    digests = {run(ir, _WD, World(workloads.endpoints("W2"))).final_digest for _ in range(100)}
    out["W2_stochastic_control"] = {"runs": 100, "distinct_digests": len(digests)}
    return out


def main():
    global _WD
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--only", choices=["repair"], help="rerun one section into bench.json")
    a = ap.parse_args()
    RESULTS.mkdir(exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="tdg-bench-")
    _WD = workloads.prepare_workdir(tmp)

    env = {"python": platform.python_version(), "machine": platform.machine(),
           "processor": platform.processor(), "cpus": os.cpu_count(), "platform": platform.platform()}
    if a.only:
        out = RESULTS / "bench.json"
        results = json.loads(out.read_text())
        results[a.only] = {"repair": lambda: repair_trials(25)}[a.only]()
        out.write_text(json.dumps(results, indent=2, default=str))
        return
    steps = [
        ("lexical", lexical),
        ("scaling", lambda: scaling([1, 5, 20, 100, 1000] if not a.quick else [1, 20])),
        ("scheduling", lambda: scheduling(reps=3 if a.quick else 7)),
        ("capabilities", lambda: capability_trials(_WD)),
        ("capabilities_naive_shell", lambda: capability_trials(_WD, shell_matching="line")),
        ("check_latency", lambda: check_latency(_WD)),
        ("repair", lambda: repair_trials(5 if a.quick else 25)),
        ("determinism", lambda: determinism(50 if a.quick else 2000)),
    ]
    results = {"environment": env}
    for key, fn in steps:
        t0 = time.perf_counter()
        print(f"{key}...", flush=True)
        results[key] = fn()
        print(f"{key} done in {time.perf_counter() - t0:.1f}s", flush=True)
    (RESULTS / ("bench_quick.json" if a.quick else "bench.json")).write_text(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
