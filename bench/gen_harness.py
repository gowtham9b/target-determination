"""Run one generated Python solution against a simulated world, with auditing.

Usage: python gen_harness.py CODE WORLD_JSON WORKDIR OUT_JSON

The solution defines main(env). env offers the same operations as TDG's
built-in tools. Every env call is logged, and a sys.addaudithook hook logs
file, network and process operations that bypass env.
"""

import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tdg.ops import World  # noqa: E402

code_path, world_path, workdir, out_path = sys.argv[1:5]
log, bypass, inside = [], [], [False]


class Env:
    def __init__(self, world):
        self._w = world

    def _call(self, entry, fn):
        log.append(entry)
        inside[0] = True
        try:
            return fn()
        finally:
            inside[0] = False

    def http_get(self, url):
        return self._call({"op": "net", "target": str(url)}, lambda: self._w.http_get(str(url)))

    def read_file(self, path):
        def go():
            with open(os.path.join(workdir, str(path)), encoding="utf-8") as f:
                return f.read()
        return self._call({"op": "read", "target": os.path.normpath(str(path))}, go)

    def write_file(self, path, text):
        def go():
            p = os.path.join(workdir, str(path))
            os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                return f.write(str(text))
        return self._call({"op": "write", "target": os.path.normpath(str(path))}, go)

    def run(self, argv):
        argv = [str(a) for a in argv]
        return self._call({"op": "shell", "target": argv}, lambda: self._w.run(argv, cwd=workdir))

    def model(self, model_id, prompt):
        return self._call({"op": "model", "target": str(model_id), "words": len(str(prompt).split())},
                          lambda: self._w.model(str(model_id), str(prompt), False))


def hook(event, args):
    if inside[0]:
        return
    if event == "open" and isinstance(args[0], (str, bytes)) and not str(args[0]).endswith((".py", ".pyc")):
        mode = args[1] if len(args) > 1 and isinstance(args[1], str) else "r"
        if "site-packages" not in str(args[0]) and "/lib/python" not in str(args[0]):
            bypass.append({"op": "open", "target": str(args[0]), "mode": mode})
    elif event in ("socket.connect", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"):
        bypass.append({"op": event, "target": repr(args)[:200]})


world = World(json.load(open(world_path)))
src = open(code_path).read()
os.chdir(workdir)
result = {"ok": False}
try:
    ns = {"__name__": "solution"}
    sys.addaudithook(hook)
    exec(compile(src, "solution.py", "exec"), ns)
    value = ns["main"](Env(world))
    result = {"ok": True, "value": json.loads(json.dumps(value, default=str))}
except BaseException as e:  # noqa: BLE001 - any failure of the solution is a result
    result = {"ok": False, "error": f"{type(e).__name__}: {e}", "traceback": traceback.format_exc()[-1500:]}
result.update(log=log, bypass=bypass)
inside[0] = True
with open(out_path, "w") as f:
    json.dump(result, f)
