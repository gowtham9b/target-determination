"""Experiments added in response to the ICoABCD reviews. Writes results/icoabcd.json.

Usage: python bench/run_icoabcd.py [--only name,...] [--quick]

Sections: taskbench, conflicts, url_fuzz, path_fuzz, shell_fuzz, toctou, http, repair_gate,
mutations, overhead, baselines. Sections that need sandbox-exec or the network must run outside
any enclosing sandbox.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import posixpath
import random
import shutil
import statistics
import string
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]

import run_bench  # noqa: E402
import taskbench  # noqa: E402
import workloads  # noqa: E402
from tdg.capabilities import CapabilityDenied, Enforcer, Gate  # noqa: E402
from tdg.compiler import compile_program, serialize_conflicts, validate  # noqa: E402
from tdg.core import (  # noqa: E402
    BRANCHES, TOOLS, TRANSFORMS, Capability, Program, Stage, program_from_dict, program_to_dict,
)
from tdg.ops import HttpWorld, World  # noqa: E402
from tdg.parser import parse, to_text  # noqa: E402
from tdg.repair import (  # noqa: E402
    apply_patch, authority_requests_for_diagnostic, authority_requests_for_event, propose_for_diagnostic,
    propose_for_event,
)
from tdg.runtime import Runtime, run  # noqa: E402

RESULTS = HERE / "results"


def pct(a, b):
    return round(100 * a / b, 1) if b else None


def median(xs):
    return round(statistics.median(xs), 3) if xs else None


# ------------------------------------------------------------ B1: TaskBench

def taskbench_eval(latency_sample=300, latency_s=0.005, seed=0):
    rng = random.Random(seed)
    per_domain, timing, valid_multi = {}, {k: [] for k in ("issue_us", "gate_us", "work_us", "predicate_us",
                                                            "trace_us")}, []
    wd = workloads.prepare_workdir(tempfile.mkdtemp(prefix="tb-"))
    for d in taskbench.DOMAINS:
        st = {"samples": 0, "malformed": 0, "invalid": 0, "valid": 0, "codes": {}, "one_based_refs": 0,
              "determined_seq": 0, "determined_par": 0, "digest_equal": 0, "stages": [], "depth": [],
              "width": [], "tools": [], "authority_ratio": [], "confinement_trials": 0, "confinement_denied": 0}
        for r in taskbench.load(d):
            st["samples"] += 1
            p, notes = taskbench.convert(r)
            if p is None:
                st["malformed"] += 1
                continue
            st["one_based_refs"] += notes["ref_offset"] == 1
            diags = validate(p)
            if diags:
                st["invalid"] += 1
                for c in {x.code for x in diags}:
                    st["codes"][c] = st["codes"].get(c, 0) + 1
                continue
            st["valid"] += 1
            ir = compile_program(p)
            n_tool = len(ir.program.stages) - 1
            st["stages"].append(n_tool)
            st["depth"].append(len(ir.levels) - 1)
            st["width"].append(max(len(lv) for lv in ir.levels[:-1]) if n_tool else 0)
            k = len(p.caps)
            st["tools"].append(k)
            if k >= 2:
                st["authority_ratio"].append(1 / k)
            seq, par = run(ir, wd, World()), run(ir, wd, World(), parallel=True)
            st["determined_seq"] += seq.determined
            st["determined_par"] += par.determined
            st["digest_equal"] += seq.final_digest == par.final_digest
            for tr in seq.traces.values():
                for key, v in tr.timing.items():
                    timing[key].append(v)
            if n_tool >= 3:
                valid_multi.append((d, ir))
            if k >= 2 and rng.random() < 0.2:
                # a compromised stage tries every other tool of its graph through its own gate
                e = Enforcer(wd)
                for s in ir.program.stages[:-1]:
                    g = Gate(e, s.name, [e.issue(s.name, ir.program.cap(u)) for u in s.uses], World())
                    for c in p.caps:
                        if c.name in s.uses:
                            continue
                        st["confinement_trials"] += 1
                        try:
                            g.custom(c.config, "{}")
                        except CapabilityDenied:
                            st["confinement_denied"] += 1
        for key in ("stages", "depth", "width", "tools", "authority_ratio"):
            xs = st.pop(key)
            st[f"{key}_mean"] = round(statistics.mean(xs), 3) if xs else None
            st[f"{key}_max"] = max(xs) if xs else None
        per_domain[d] = st
    speed = []
    for d, ir in rng.sample(valid_multi, min(latency_sample, len(valid_multi))):
        t0 = time.perf_counter()
        run(ir, wd, World(latency_s=latency_s))
        t1 = time.perf_counter()
        run(ir, wd, World(latency_s=latency_s), parallel=True)
        t2 = time.perf_counter()
        speed.append({"domain": d, "stages": len(ir.program.stages) - 1, "depth": len(ir.levels) - 1,
                      "seq_ms": (t1 - t0) * 1000, "par_ms": (t2 - t1) * 1000})
    shutil.rmtree(wd, ignore_errors=True)
    sp = [x["seq_ms"] / x["par_ms"] for x in speed]
    return {"per_domain": per_domain,
            "timing_us_median": {k: median(v) for k, v in timing.items()},
            "timing_us_p95": {k: round(sorted(v)[int(0.95 * len(v))], 3) for k, v in timing.items() if v},
            "latency_ms": latency_s * 1000, "speedup": {"n": len(sp), "median": median(sp),
                                                         "max": round(max(sp), 2) if sp else None,
                                                         "share_over_1_2": pct(sum(x > 1.2 for x in sp), len(sp))},
            "speed_rows": speed}


# ------------------------------------------------------------ A5: schedule equivalence

def _conflict_program(rng):
    paths = ["out/a.txt", "out/b.txt", "out/./a.txt", "out/alias/a.txt"]
    caps = (Capability("out", "fs", root="out", mode="rw"),)
    stages, reads = [], []
    for i in range(rng.randint(2, 6)):
        if rng.random() < 0.6:
            stages.append(Stage(f"w{i}", "tool", "fs.write", uses=("out",),
                                args=(("path", rng.choice(paths)), ("text", f"v{i}"))))
        else:
            stages.append(Stage(f"r{i}", "tool", "fs.read", uses=("out",), args=(("path", rng.choice(paths)),),
                                on_fail=__import__("tdg.core", fromlist=["Policy"]).Policy("propose")))
            reads.append(f"r{i}")
    stages.append(Stage("result", "output", after=tuple(s.name for s in stages), inputs=tuple(reads)))
    return Program(caps, tuple(stages))


def conflicts_eval(n_programs=200, runs=20, seed=0):
    rng = random.Random(seed)
    out = {"programs": n_programs, "runs_per_mode": 2 * runs}
    for serialize in (False, True):
        diverged, extra_levels, lexical_warned = 0, [], 0
        rng = random.Random(seed)
        for _ in range(n_programs):
            p = _conflict_program(rng)
            ir = compile_program(p)
            lexical_warned += bool(ir.warnings)
            outcomes = set()
            for k in range(2 * runs):
                wd = workloads.prepare_workdir(tempfile.mkdtemp(prefix="cf-"))
                os.symlink(os.path.join(wd, "out"), os.path.join(wd, "out", "alias"))
                rt = Runtime(ir, wd, World(storage_jitter_s=0.001), parallel=bool(k % 2), serialize=serialize)
                if serialize:
                    extra_levels.append(len(rt.plan) - len(ir.levels))
                r = rt.run()
                files = tuple(sorted((f, Path(wd, "out", f).read_text()) for f in os.listdir(os.path.join(wd, "out"))
                                     if f != "alias"))
                outcomes.add((r.status, json.dumps(r.outputs, sort_keys=True, default=str), files))
                shutil.rmtree(wd, ignore_errors=True)
            diverged += len(outcomes) > 1
        out["serialized" if serialize else "unserialized"] = {
            "programs_with_divergent_outcomes": diverged,
            "programs_with_lexical_warning": lexical_warned,
            "mean_extra_levels": round(statistics.mean(extra_levels), 3) if extra_levels else 0}
    # the five workloads keep their schedule
    out["workload_extra_levels"] = {
        n: len(Runtime(compile_program(parse(src)), tempfile.gettempdir()).plan) - len(compile_program(parse(src)).levels)
        for n, src in workloads.SOURCES.items()}
    return out


# ------------------------------------------------------------ A2: URL fuzzing against independent parsers

ALLOWED = "https://api.example.com/v1/*"


def _url_corpus(rng, per_template=25):
    w = lambda: "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(3, 8)))  # noqa: E731
    H, E = "api.example.com", "evil.example.net"
    t = [
        ("benign", lambda: f"https://{H}/v1/{w()}"),
        ("benign_query", lambda: f"https://{H}/v1/{w()}?q={w()}"),
        ("userinfo_host_first", lambda: f"https://{H}@{E}/v1/{w()}"),
        ("userinfo_evil_first", lambda: f"https://{E}@{H}/v1/{w()}"),
        ("userinfo_port", lambda: f"https://{H}:443@{E}/v1/{w()}"),
        ("credentials", lambda: f"https://u:p@{H}/v1/{w()}"),
        ("backslash_evil_first", lambda: f"https://{E}\\@{H}/v1/{w()}"),
        ("backslash_host_first", lambda: f"https://{H}\\@{E}/v1/{w()}"),
        ("backslash_path", lambda: f"https://{H}\\v1\\{w()}"),
        ("backslash_scheme", lambda: f"https:\\\\{E}/v1/{w()}"),
        ("encoded_at", lambda: f"https://{H}%40{E}/v1/{w()}"),
        ("encoded_slash_host", lambda: f"https://{H}%2F@{E}/v1/{w()}"),
        ("encoded_hash", lambda: f"https://{E}%23@{H}/v1/{w()}"),
        ("encoded_dot_host", lambda: f"https://api%2Eexample.com/v1/{w()}"),
        ("fragment_at", lambda: f"https://{E}#@{H}/v1/{w()}"),
        ("query_at", lambda: f"https://{E}?@{H}/v1/{w()}"),
        ("dot_segments", lambda: f"https://{H}/v1/../{w()}"),
        ("encoded_dot_segments", lambda: f"https://{H}/v1/%2e%2e/{w()}"),
        ("encoded_slash_path", lambda: f"https://{H}/v1/..%2f{w()}"),
        ("tab_in_host", lambda: f"https://api.exa\tmple.com/v1/{w()}"),
        ("newline_in_host", lambda: f"https://{E}\n@{H}/v1/{w()}"),
        ("space_before_at", lambda: f"https://{E} @{H}/v1/{w()}"),
        ("leading_space", lambda: f" https://{E}/v1/{w()}"),
        ("uppercase_host", lambda: f"https://API.EXAMPLE.COM/v1/{w()}"),
        ("uppercase_scheme", lambda: f"HTTPS://{H}/v1/{w()}"),
        ("trailing_dot", lambda: f"https://{H}./v1/{w()}"),
        ("homoglyph", lambda: f"https://api.ex\u0430mple.com/v1/{w()}"),
        ("fullwidth_dot", lambda: f"https://api\uff0eexample\uff0ecom/v1/{w()}"),
        ("punycode", lambda: f"https://xn--api-example-{w()}.com/v1/{w()}"),
        ("ip_metadata", lambda: f"https://169.254.169.254/v1/{w()}"),
        ("ip_decimal", lambda: f"https://2852039166/v1/{w()}"),
        ("ip_hex", lambda: f"https://0xa9fea9fe/v1/{w()}"),
        ("ipv6_mapped", lambda: f"https://[::ffff:a9fe:a9fe]/v1/{w()}"),
        ("default_port", lambda: f"https://{H}:443/v1/{w()}"),
        ("other_port", lambda: f"https://{H}:8443/v1/{w()}"),
        ("padded_port", lambda: f"https://{H}:0443/v1/{w()}"),
        ("http_scheme", lambda: f"http://{H}/v1/{w()}"),
        ("single_slash", lambda: f"https:/{H}/v1/{w()}"),
        ("triple_slash", lambda: f"https:///{E}/v1/{w()}"),
        ("suffix_host", lambda: f"https://{H}.{E}/v1/{w()}"),
    ]
    return [(name, gen()) for name, gen in t for _ in range(per_template)]


def _remove_dots(path: str) -> str:
    out = []
    for seg in path.split("/"):
        if seg == "..":
            if len(out) > 1:
                out.pop()
        elif seg != ".":
            out.append(seg)
    return "/".join(out) or "/"


def _oracles():
    import ada_url
    import httpx
    import urllib3

    def via_urllib3(u):
        x = urllib3.util.parse_url(u)
        return x.scheme, x.host, x.port, x.path or "/"

    def via_httpx(u):
        x = httpx.URL(u)
        return x.scheme, x.host, x.port, x.raw_path.decode().split("?")[0] or "/"

    def via_whatwg(u):
        x = ada_url.URL(u)
        return x.protocol.rstrip(":"), x.hostname, int(x.port) if x.port else None, x.pathname or "/"
    return {"requests/urllib3": via_urllib3, "httpx": via_httpx, "WHATWG (ada)": via_whatwg}


def _destination_allowed(dest) -> bool:
    scheme, host, port, path = dest
    path = _remove_dots(unquote(path).replace("\\", "/"))
    return (str(scheme).lower() == "https" and str(host).lower().rstrip(".") == "api.example.com"
            and port in (None, 443) and path.startswith("/v1/"))


def url_fuzz(per_template=25, seed=0):
    rng = random.Random(seed)
    corpus = _url_corpus(rng, per_template)
    oracles = _oracles()
    wd = tempfile.mkdtemp(prefix="uf-")
    cap = Capability("api", "net", allow=(ALLOWED,))
    res = {"n": len(corpus), "templates": len({c for c, _ in corpus}), "modes": {}}
    for mode in ("lenient", "strict"):
        e = Enforcer(wd, url_check=mode)
        tok = e.issue("s", cap)
        bypass, false_deny, by_template = {k: 0 for k in oracles}, 0, {}
        for name, u in corpus:
            try:
                e.check_net("s", tok, u)
                allowed = True
            except CapabilityDenied:
                allowed = False
            dests = {}
            for k, f in oracles.items():
                try:
                    dests[k] = f(u)
                except Exception:  # noqa: BLE001 - a client that rejects the URL sends nothing
                    dests[k] = None
            bad = [k for k, d in dests.items() if d is not None and not _destination_allowed(d)]
            good = all(d is not None and _destination_allowed(d) for d in dests.values())
            if allowed:
                for k in bad:
                    bypass[k] += 1
            elif good:
                false_deny += 1
            row = by_template.setdefault(name, {"allowed": 0, "bypass_any": 0})
            row["allowed"] += allowed
            row["bypass_any"] += allowed and bool(bad)
        res["modes"][mode] = {"allowed": sum(v["allowed"] for v in by_template.values()),
                              "bypass_by_client": bypass,
                              "bypass_any": sum(v["bypass_any"] for v in by_template.values()),
                              "false_denials": false_deny,
                              "bypass_templates": sorted(k for k, v in by_template.items() if v["bypass_any"])}
    # parsers disagreeing among themselves on the corpus
    safe = [_safe(f) for f in oracles.values()]
    res["parser_disagreements"] = sum(len({json.dumps(g(u), default=str) for g in safe}) > 1 for _, u in corpus)
    shutil.rmtree(wd, ignore_errors=True)
    return res


def _safe(f):
    def g(u):
        try:
            d = f(u)
            return (str(d[0]).lower(), str(d[1]).lower(), d[2] if d[2] not in (443,) else None)
        except Exception:  # noqa: BLE001
            return None
    return g


# ------------------------------------------------------------ A2/A6: path fuzzing with an inode oracle

def _fs_fixture():
    wd = workloads.prepare_workdir(tempfile.mkdtemp(prefix="pf-"))
    os.makedirs(os.path.join(wd, "data", "sub"), exist_ok=True)
    for name in ("secret.csv", "keys.txt"):
        Path(wd, "private", name).write_text("SECRET\n")
    for name in ("f0.csv", "sub/f1.csv"):
        Path(wd, "data", name).write_text("public\n")
    os.symlink("../private/secret.csv", os.path.join(wd, "data", "link_priv"))
    os.symlink("../private", os.path.join(wd, "data", "link_dir"))
    os.symlink("f0.csv", os.path.join(wd, "data", "link_ok"))
    os.link(os.path.join(wd, "private", "keys.txt"), os.path.join(wd, "data", "alias.txt"))
    return wd


def _inodes(root):
    out = set()
    for dp, _, fs in os.walk(root):
        for f in fs:
            st = os.lstat(os.path.join(dp, f))
            if not os.path.islink(os.path.join(dp, f)):
                out.add((st.st_dev, st.st_ino))
    return out


def path_fuzz(n=2000, seed=0):
    rng = random.Random(seed)
    wd = _fs_fixture()
    private = _inodes(os.path.join(wd, "private"))
    comps = ["data", "private", "..", ".", "", "sub", "link_priv", "link_dir", "link_ok", "alias.txt", "f0.csv",
             "f1.csv", "secret.csv", "keys.txt", "events.csv", "DATA", "Private", "%2e%2e", "~", "data/"]
    paths = []
    for _ in range(n):
        p = "/".join(rng.choice(comps) for _ in range(rng.randint(1, 5)))
        if rng.random() < 0.1:
            p = os.path.join(wd, p)
        paths.append(p)
    cap = Capability("d", "fs", root="data", mode="read")
    res = {"n": n, "modes": {}}
    for mode in ("path", "descriptor"):
        e = Enforcer(wd, fs_check=mode)
        tok = e.issue("s", cap)
        leaks, allowed, opened = 0, 0, 0
        for p in paths:
            try:
                fd = e.open_fs("s", tok, p, "read")
            except (CapabilityDenied, OSError):
                continue
            allowed += 1
            st = os.fstat(fd)
            os.close(fd)
            if stat_is_reg(st):
                opened += 1
                leaks += (st.st_dev, st.st_ino) in private
        res["modes"][mode] = {"allowed": allowed, "regular_files_opened": opened, "private_file_reads": leaks}
    shutil.rmtree(wd, ignore_errors=True)
    return res


def stat_is_reg(st):
    import stat
    return stat.S_ISREG(st.st_mode)


# ------------------------------------------------------------ A2/A6: shell argument fuzzing, OS sandbox as oracle

def shell_fuzz(n=400, seed=0):
    rng = random.Random(seed)
    wd = _fs_fixture()
    Path(wd, "private", "k.csv").write_text("SECRET\n")
    toks = ["data/f0.csv", "data/sub/f1.csv", "data/../private/k.csv", "private/k.csv", "data/link_priv",
            "data/link_dir/k.csv", "data/*.csv", os.path.join(wd, "private", "k.csv"), "data/./f0.csv",
            "data/alias.txt", "-c", "-w", "-l", "--", ";", "data/f0.csv;cat", "$(cat private/k.csv)", "data/events.csv"]
    argvs = [["wc", "-l"] + [rng.choice(toks) for _ in range(rng.randint(1, 3))] for _ in range(n)]
    cap = Capability("sh", "shell", allow=("wc -l data/*.csv",))
    oracle = Enforcer(wd, shell_matching="line")  # used only to build the oracle profile
    otok = oracle.issue("s", cap)

    def reads_outside(argv):
        """Run under a sandbox that only denies reads outside data/; report attempted escapes."""
        p = subprocess.run(oracle.sandbox_argv(otok, argv), cwd=wd, capture_output=True, text=True, timeout=10)
        return "Operation not permitted" in p.stderr

    truth = [reads_outside(a) for a in argvs]
    res = {"n": n, "escape_attempts": sum(truth), "matchers": {}}
    for matching in ("line", "argv"):
        e = Enforcer(wd, shell_matching=matching)
        tok = e.issue("s", cap)
        admitted, bypass = 0, 0
        for a, bad in zip(argvs, truth):
            try:
                e.check_shell("s", tok, a)
            except CapabilityDenied:
                continue
            admitted += 1
            bypass += bad
        res["matchers"][matching] = {"admitted": admitted, "admitted_escapes": bypass,
                                     "escapes_stopped_by_os_sandbox": bypass}
    shutil.rmtree(wd, ignore_errors=True)
    return res


# ------------------------------------------------------------ A6: check-to-use race

def _swapper(wd, stop, kind):
    sub, real, priv = (os.path.join(wd, "data", "sub"), os.path.join(wd, "data", "sub_real"),
                       os.path.join(wd, "private"))
    while not stop.is_set():
        try:
            os.rename(sub, real)
            os.symlink(priv, sub)
            os.unlink(sub)
            os.rename(real, sub)
        except OSError:
            pass


def toctou(attempts=20000):
    res = {}
    for mode in ("path", "descriptor"):
        wd = workloads.prepare_workdir(tempfile.mkdtemp(prefix="tt-"))
        os.makedirs(os.path.join(wd, "data", "sub"))
        Path(wd, "data", "sub", "f.csv").write_text("public\n")
        Path(wd, "private", "f.csv").write_text("SECRET\n")
        e = Enforcer(wd, fs_check=mode)
        tok = e.issue("s", Capability("d", "fs", root="data", mode="rw"))
        g = Gate(e, "s", [tok], World())
        stop = mp.Event()
        proc = mp.Process(target=_swapper, args=(wd, stop, "dir"))
        proc.start()
        reads = {"public": 0, "secret": 0, "denied": 0, "error": 0}
        writes_escaped = 0
        try:
            for i in range(attempts):
                try:
                    v = g.read_file("data/sub/f.csv")
                    reads["secret" if "SECRET" in v else "public"] += 1
                except CapabilityDenied:
                    reads["denied"] += 1
                except OSError:
                    reads["error"] += 1
                if i % 4 == 0:
                    try:
                        g.write_file(f"data/sub/w{i}.txt", "x")
                    except (CapabilityDenied, OSError):
                        pass
        finally:
            stop.set()
            proc.join()
        writes_escaped = len([f for f in os.listdir(os.path.join(wd, "private")) if f.startswith("w")])
        res[mode] = {"attempts": attempts, **reads, "writes_landing_outside_root": writes_escaped}
        shutil.rmtree(wd, ignore_errors=True)
    return res


# ------------------------------------------------------------ A2: real HTTP

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/v1/orders"):
            body = json.dumps({"orders": [{"id": i} for i in range(42)]}).encode()
            self.send_response(200)
        elif self.path.startswith("/v1/redirect"):
            body = b""
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        elif self.path.startswith("/v1/slow"):
            time.sleep(3)
            body = b"late"
            self.send_response(200)
        elif self.path.startswith("/v1/big"):
            body = b"x" * (2 << 20)
            self.send_response(200)
        else:
            body = b""
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def http_eval(live=True, runs=50):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    base = f"http://localhost:{port}"
    wd = workloads.prepare_workdir(tempfile.mkdtemp(prefix="hw-"))
    src = workloads.W1.replace("https://api.example.com/*", f"{base}/v1/*").replace(
        "https://api.example.com/orders", f"{base}/v1/orders")
    ir = compile_program(parse(src))
    digests, det, lat = set(), 0, []
    for _ in range(runs):
        t0 = time.perf_counter()
        r = run(ir, wd, HttpWorld(timeout_s=1.0))
        lat.append((time.perf_counter() - t0) * 1000)
        det += r.determined
        digests.add(r.final_digest)
    out = {"local": {"runs": runs, "determined": det, "distinct_digests": len(digests), "median_ms": median(lat)}}
    cases = {}
    for name, path in (("redirect_to_metadata", "/v1/redirect"), ("slow", "/v1/slow"), ("oversized", "/v1/big")):
        prog = parse(f'cap net api{{allow "{base}/v1/*";}}stage f:tool net.get{{uses api;arg url="{base}{path}";'
                     f'check status 200..299;viol propose;fail propose;}}stage o:output{{after f;}}')
        r = run(compile_program(prog), wd, HttpWorld(timeout_s=1.0))
        t = r.traces["f"]
        cases[name] = {"status": t.status, "error": t.error, "observed": [c["observed"] for c in t.checks]}
    # a resolver that changes its answer between two lookups (DNS rebinding)
    answers = iter(["127.0.0.1", "169.254.169.254"])
    prog = parse(f'cap net api{{allow "http://rebind.test:{port}/v1/*";}}'
                 f'stage a:tool net.get{{uses api;arg url="http://rebind.test:{port}/v1/orders";fail propose;}}'
                 f'stage b:tool net.get{{after a;uses api;arg url="http://rebind.test:{port}/v1/orders";fail propose;}}'
                 f'stage o:output{{after a,b;}}')
    r = run(compile_program(prog), wd, HttpWorld(timeout_s=1.0, resolver=lambda h, p: next(answers)))
    cases["dns_rebinding"] = {"first": r.traces["a"].status, "second": r.traces["b"].status,
                              "error": r.traces["b"].error}
    out["cases"] = cases
    srv.shutdown()
    if live:
        prog = parse('cap net gh{allow "https://api.github.com/repos/microsoft/JARVIS";}'
                     'stage f:tool net.get{uses gh;arg url="https://api.github.com/repos/microsoft/JARVIS";'
                     'check status 200..299;check maxbytes 1048576;}'
                     'stage stars:transform field{after f;arg key="stargazers_count";check min 0;}'
                     'stage o:output{after stars;}')
        ir = compile_program(prog)
        rows = []
        for _ in range(5):
            t0 = time.perf_counter()
            try:
                r = run(ir, wd, HttpWorld(timeout_s=10.0))
                rows.append({"status": r.status, "ms": round((time.perf_counter() - t0) * 1000, 1),
                             "digest": r.final_digest[:12]})
            except Exception as ex:  # noqa: BLE001
                rows.append({"error": repr(ex)[:200]})
        out["live_github"] = rows
    shutil.rmtree(wd, ignore_errors=True)
    return out


# ------------------------------------------------------------ A7: authority gate on the original repair trials

def repair_gate(per_category=25, seed=1):
    wd = workloads.prepare_workdir(tempfile.mkdtemp(prefix="rg-"))
    run_bench._WD = wd
    rng = random.Random(seed)
    cats = ["dep_typo", "input_typo", "op_typo", "cap_typo", "status_strict", "transient_5xx", "field_key_typo",
            "bound_tight", "permanent_404", "url_host_typo"]
    summary = {}
    for category in cats:
        c = summary.setdefault(category, {"n": 0, "ordinary_top1_resolves": 0, "ordinary_top1_intended": 0,
                                          "authority_requests": 0, "request_resolves_if_granted": 0,
                                          "request_restores_original": 0})
        while c["n"] < per_category:
            fault = run_bench.make_fault(category, rng)
            if fault is None:
                continue
            _, doc, eps, original = fault
            if doc == original and category not in ("transient_5xx", "status_strict", "permanent_404"):
                continue
            c["n"] += 1
            p = program_from_dict(doc)
            diags = validate(p)
            if diags:
                ords, reqs, base = propose_for_diagnostic(doc, diags[0]), authority_requests_for_diagnostic(doc, diags[0]), doc
            else:
                ir = compile_program(p)
                r = run(ir, wd, World(eps))
                if r.determined or not r.events:
                    continue
                base = program_to_dict(ir.program)
                ords, reqs = propose_for_event(base, r.events[0]), authority_requests_for_event(base, r.events[0])
            if ords:
                patched = apply_patch(base, ords[0].patch)
                ok = run_bench.evaluate(patched, eps)[0]
                c["ordinary_top1_resolves"] += ok
                intended = (ok and ords[0].kind == "retry") if category == "transient_5xx" else \
                    (ok and ords[0].kind == "relax") if category == "status_strict" else patched == original
                c["ordinary_top1_intended"] += bool(intended)
            if reqs:
                c["authority_requests"] += 1
                patched = apply_patch(base, reqs[0].patch)
                c["request_resolves_if_granted"] += run_bench.evaluate(patched, eps)[0]
                c["request_restores_original"] += patched == original
    shutil.rmtree(wd, ignore_errors=True)
    return summary


# ------------------------------------------------------------ A3/B3: generic mutations

def _ident_sites(doc):
    for i, s in enumerate(doc["stages"]):
        for f in ("after", "inputs", "uses"):
            for j, _ in enumerate(s.get(f, [])):
                yield ("list", i, f, j)
        for f in ("op", "when", "name", "out"):
            if s.get(f):
                yield ("field", i, f, None)


def mutate(doc, rng):
    """One random edit drawn from generic operators, independent of the repair rules."""
    d = json.loads(json.dumps(doc))
    stages = d["stages"]
    names = [s["name"] for s in stages]
    ops = ["drop_dep", "add_dep", "drop_stage", "op_swap", "arg_value", "arg_key", "drop_uses", "swap_uses",
           "ident_typo", "drop_check", "add_check", "policy"]
    for _ in range(50):
        op = rng.choice(ops)
        s = rng.choice(stages)
        if op == "drop_dep" and s.get("after"):
            s["after"].pop(rng.randrange(len(s["after"])))
        elif op == "add_dep":
            cand = [n for n in names if n != s["name"] and n not in s.get("after", [])]
            if not cand:
                continue
            s.setdefault("after", []).append(rng.choice(cand))
        elif op == "drop_stage" and s["kind"] != "output" and len(stages) > 2:
            stages.remove(s)
        elif op == "op_swap" and s.get("op"):
            table = {"tool": TOOLS, "transform": TRANSFORMS, "branch": BRANCHES}[s["kind"]]
            cand = [o for o in table if o != s["op"]]
            s["op"] = rng.choice(cand)
        elif op == "arg_value" and s.get("args"):
            k = rng.choice(sorted(s["args"]))
            v = s["args"][k]
            if isinstance(v, bool):
                s["args"][k] = not v
            elif isinstance(v, (int, float)):
                s["args"][k] = v + rng.choice([-1, 1, 10, -10]) if rng.random() < 0.5 else v * 2
            else:
                t = run_bench.typo(str(v), rng, set())
                if t is None:
                    continue
                s["args"][k] = t
        elif op == "arg_key" and s.get("args"):
            k = rng.choice(sorted(s["args"]))
            t = run_bench.typo(k, rng, set(s["args"]))
            if t is None:
                continue
            s["args"][t] = s["args"].pop(k)
        elif op == "drop_uses" and s.get("uses"):
            s["uses"].pop(rng.randrange(len(s["uses"])))
        elif op == "swap_uses" and s.get("uses"):
            cand = [c["name"] for c in d["caps"] if c["name"] not in s["uses"]]
            if not cand:
                continue
            s["uses"][0] = rng.choice(cand)
        elif op == "ident_typo":
            sites = list(_ident_sites(d))
            kind, i, f, j = rng.choice(sites)
            cur = stages[i][f][j] if kind == "list" else stages[i][f]
            t = run_bench.typo(str(cur), rng, set(names))
            if t is None:
                continue
            if kind == "list":
                stages[i][f][j] = t
            else:
                stages[i][f] = t
        elif op == "drop_check" and s.get("checks"):
            s["checks"].pop(rng.randrange(len(s["checks"])))
        elif op == "add_check" and s["kind"] != "output":
            s.setdefault("checks", []).append(rng.choice([{"op": "nonempty", "args": []}, {"op": "max", "args": [1]},
                                                          {"op": "maxbytes", "args": [8]}]))
        elif op == "policy" and s["kind"] == "tool":
            s["on_violation"] = rng.choice([{"action": "abort", "count": 0}, {"action": "retry", "count": 1},
                                            {"action": "propose", "count": 0}])
        else:
            continue
        if d != doc:
            return op, d
    return None, None


def _outcome(doc, eps, wd):
    p = program_from_dict(doc)
    diags = validate(p)
    if diags:
        return "compile", None, diags[0], doc
    ir = compile_program(p)
    r = run(ir, wd, World(eps))
    if r.determined:
        return "determined", r.outputs, None, None
    if not r.events:
        return "blocked", None, None, None
    return "runtime", None, r.events[0], program_to_dict(ir.program)


def mutations(n_per_base=60, taskbench_bases=2000, seed=2):
    rng = random.Random(seed)
    wd = workloads.prepare_workdir(tempfile.mkdtemp(prefix="mu-"))
    bases = [("workload", program_to_dict(parse(src)), workloads.endpoints(n)) for n, src in workloads.SOURCES.items()]
    pool = []
    for d in taskbench.DOMAINS:
        for r in taskbench.load(d):
            p, _ = taskbench.convert(r)
            if p is not None and not validate(p) and len(p.stages) >= 3:
                pool.append(program_to_dict(p))
    bases += [("taskbench", b, {}) for b in rng.sample(pool, taskbench_bases)]
    rows = []
    for source, doc, eps in bases:
        ref = _outcome(doc, eps, wd)[1]
        for _ in range(n_per_base if source == "workload" else 1):
            op, m = mutate(doc, rng)
            if m is None:
                continue
            kind, outputs, event, base = _outcome(m, eps, wd)
            row = {"source": source, "op": op, "kind": kind}
            if kind == "determined":
                row["kind"] = "equivalent" if json.dumps(outputs, sort_keys=True, default=str) == \
                    json.dumps(ref, sort_keys=True, default=str) else "silently_wrong"
            elif kind in ("compile", "runtime"):
                for rank in ("confidence", "cost"):
                    props = (propose_for_diagnostic(base, event, rank=rank) if kind == "compile"
                             else propose_for_event(base, event, rank=rank))
                    reqs = (authority_requests_for_diagnostic(base, event) if kind == "compile"
                            else authority_requests_for_event(base, event))
                    res = []
                    for pr in props[:3]:
                        try:
                            patched = apply_patch(base, pr.patch)
                            ok = _outcome(patched, eps, wd)
                            res.append((ok[0] == "determined", patched == (doc if kind == "compile" else
                                                                           program_to_dict(compile_program(program_from_dict(doc)).program))))
                        except Exception:  # noqa: BLE001
                            res.append((False, False))
                    rank_of_intended = next((i + 1 for i, (_, intended) in enumerate(res) if intended), None)
                    row[rank] = {"proposals": len(props), "authority_requests": len(reqs),
                                 "top1_resolves": bool(res and res[0][0]), "top1_intended": bool(res and res[0][1]),
                                 "rr": 1 / rank_of_intended if rank_of_intended else 0.0,
                                 "top1": json.dumps(props[0].patch) if props else None,
                                 "any_intended": any(i for _, i in res)}
            rows.append(row)
    shutil.rmtree(wd, ignore_errors=True)
    summary = {}
    for src in ("workload", "taskbench"):
        rs = [r for r in rows if r["source"] == src]
        s = {"n": len(rs), **{k: sum(r["kind"] == k for r in rs) for k in
                               ("equivalent", "silently_wrong", "compile", "runtime", "blocked")}}
        det = [r for r in rs if r["kind"] in ("compile", "runtime")]
        for rank in ("confidence", "cost"):
            s[rank] = {"detected": len(det),
                       "with_proposal": sum(r[rank]["proposals"] > 0 for r in det),
                       "with_authority_request": sum(r[rank]["authority_requests"] > 0 for r in det),
                       "top1_resolves": sum(r[rank]["top1_resolves"] for r in det),
                       "top1_intended": sum(r[rank]["top1_intended"] for r in det),
                       "mrr_intended": round(statistics.mean([r[rank]["rr"] for r in det]), 3) if det else None,
                       "intended_in_top3": sum(r[rank]["any_intended"] for r in det)}
        multi = [r for r in det if r["confidence"]["proposals"] >= 2]
        s["multi_proposal"] = len(multi)
        s["top1_agree"] = sum(r["confidence"]["top1"] == r["cost"]["top1"] for r in multi)
        s["by_op"] = {op: {k: sum(r["op"] == op and r["kind"] == k for r in rs)
                           for k in ("equivalent", "silently_wrong", "compile", "runtime", "blocked")}
                      for op in sorted({r["op"] for r in rs})}
        summary[src] = s
    return {"summary": summary, "rows": rows}


# ------------------------------------------------------------ B4: overhead

def overhead(runs=300):
    wd = workloads.prepare_workdir(tempfile.mkdtemp(prefix="oh-"))
    per = {}
    for name, src in workloads.SOURCES.items():
        ir = compile_program(parse(src))
        acc = {kind: {k: [] for k in ("issue_us", "gate_us", "work_us", "predicate_us", "trace_us", "wall_us")}
               for kind in ("tool", "pure")}
        for _ in range(runs):
            r = run(ir, wd, World(workloads.endpoints(name)))
            for n, tr in r.traces.items():
                if tr.timing:
                    a = acc["tool" if ir.program.stage(n).kind == "tool" else "pure"]
                    a["wall_us"].append(tr.wall_ms * 1000)
                    for k, v in tr.timing.items():
                        a[k].append(v)
        per[name] = {kind: {k: median(v) for k, v in a.items()} for kind, a in acc.items()}
    e = Enforcer(wd)
    micro = {}
    for mode in ("path", "descriptor"):
        em = Enforcer(wd, fs_check=mode)
        tok = em.issue("s", Capability("d", "fs", root="data", mode="read"))
        g = Gate(em, "s", [tok], World())
        micro[f"fs_read_{mode}_us"] = run_bench.timed(lambda: g.read_file("data/events.csv")) * 1000
    for mode in ("lenient", "strict"):
        en = Enforcer(wd, url_check=mode)
        tok = en.issue("s", Capability("n", "net", allow=(ALLOWED,)))
        micro[f"net_check_{mode}_us"] = run_bench.timed(lambda: en.check_net("s", tok, "https://api.example.com/v1/x")) * 1000
    for sandbox in (False, True):
        es = Enforcer(wd, shell_sandbox=sandbox)
        g = Gate(es, "s", [es.issue("s", Capability("sh", "shell", allow=("wc -l data/*.csv",)))], World())
        micro[f"shell_run_{'sandboxed' if sandbox else 'plain'}_ms"] = run_bench.timed(
            lambda: g.run(["wc", "-l", "data/events.csv"]), min_reps=20)
    micro["token_issue_us"] = run_bench.timed(lambda: e.issue("s", Capability("n", "net", allow=(ALLOWED,)))) * 1000
    shutil.rmtree(wd, ignore_errors=True)
    return {"per_workload_median": per, "micro": {k: round(v, 3) for k, v in micro.items()}}


# ------------------------------------------------------------ A4: baselines with equivalent checks

def baselines():
    import tiktoken
    enc = tiktoken.get_encoding("o200k_base")
    rows = []
    for name, src in workloads.SOURCES.items():
        b = HERE / "baselines"
        row = {"workload": name, "tdg": len(enc.encode(src))}
        for form in ("script", "airflow", "script_checked"):
            f = b / f"{name.lower()}_{form}.py"
            row[form] = len(enc.encode(f.read_text())) if f.exists() else None
        rows.append(row)
    tot = {k: sum(r[k] for r in rows if r[k] is not None) for k in ("tdg", "script", "airflow", "script_checked")}
    return {"rows": rows, "total": tot}


SECTIONS = {
    "taskbench": taskbench_eval, "conflicts": conflicts_eval, "url_fuzz": url_fuzz, "path_fuzz": path_fuzz,
    "shell_fuzz": shell_fuzz, "toctou": toctou, "http": http_eval, "repair_gate": repair_gate,
    "mutations": mutations, "overhead": overhead, "baselines": baselines,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    out = RESULTS / "icoabcd.json"
    results = json.loads(out.read_text()) if out.exists() else {}
    for name in (a.only.split(",") if a.only else SECTIONS):
        t0 = time.perf_counter()
        print(f"{name}...", flush=True)
        results[name] = SECTIONS[name]()
        print(f"{name} done in {time.perf_counter() - t0:.1f}s", flush=True)
        out.write_text(json.dumps(results, indent=1, default=str))


if __name__ == "__main__":
    main()
