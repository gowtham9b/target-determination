"""Convert TaskBench tool graphs (Shen et al., NeurIPS 2024) into TDG programs.

Data: microsoft/JARVIS, taskbench/data_*/data.json at the commit in
external/taskbench/COMMIT. Only samples in TaskBench's own "all_alignment_id"
set (those that passed all of its quality checks) are used.

Each tool node becomes a custom.call stage that holds one capability, for its
own tool. Links become dependencies; a "<node-k>" argument becomes an input
read from node k. Sinks feed one output stage. Nothing is repaired during
conversion, so inconsistencies in the published graphs reach the validator.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from tdg.core import Capability, Program, Stage

DATA = Path(__file__).resolve().parent / "external" / "taskbench"
DOMAINS = ("data_dailylifeapis", "data_huggingface", "data_multimedia")
REF = re.compile(r"^<node-(\d+)>$")


def ident(tool: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "_", tool).strip("_").lower()
    return s if s and s[0].isalpha() else f"t_{s}"


def load(domain: str) -> list[dict]:
    keep = set()
    for ids in json.loads((DATA / domain / "alignment_ids.json").read_text())["all_alignment_id"].values():
        keep.update(ids)
    rows = []
    for line in (DATA / domain / "data.json").read_text().splitlines():
        r = json.loads(line)
        if r["id"] in keep:
            r["nodes"], r["links"] = json.loads(r["tool_nodes"]), json.loads(r["tool_links"])
            rows.append(r)
    return rows


def _refs(nodes: list[dict]) -> list[tuple[int, int]]:
    out = []
    for i, n in enumerate(nodes):
        for a in n.get("arguments", []):
            m = REF.match(str(a.get("value") if isinstance(a, dict) else a))
            if m:
                out.append((int(m.group(1)), i))
    return out


def _ref_offset(nodes: list[dict], links: list) -> int:
    """TaskBench numbers "<node-k>" from 0 in some samples and from 1 in others.

    Pick the numbering under which more references agree with a declared link
    (0 on ties); references that agree under neither reach the validator.
    """
    pairs = {(x.get("source"), x.get("target")) for x in links if isinstance(x, dict)}

    def agree(off: int) -> int:
        return sum(0 <= k - off < len(nodes) and (nodes[k - off]["task"], nodes[i]["task"]) in pairs
                   for k, i in _refs(nodes))
    return 1 if agree(1) > agree(0) else 0


def convert(r: dict) -> tuple[Program | None, dict]:
    """Return the TDG program and conversion notes for one TaskBench sample.

    Samples whose nodes are not tool records cannot be expressed as stages;
    they return None with notes["malformed_nodes"] set.
    """
    nodes, links = r["nodes"], r["links"]
    if not isinstance(nodes, list) or not all(isinstance(n, dict) and isinstance(n.get("task"), str) for n in nodes):
        return None, {"malformed_nodes": True, "ambiguous_links": False, "malformed_links": 0}
    if not isinstance(links, list):
        links = []
    first: dict[str, int] = {}
    for i, n in enumerate(nodes):
        first.setdefault(n["task"], i)
    offset = _ref_offset(nodes, links)
    notes = {"malformed_nodes": False, "ambiguous_links": len(nodes) != len(first) and bool(links),
             "malformed_links": 0, "ref_offset": offset}
    after: dict[int, list[str]] = {i: [] for i in range(len(nodes))}
    has_out: set[int] = set()
    for link in links:
        if not isinstance(link, dict) or not all(isinstance(link.get(k), str) for k in ("source", "target")):
            notes["malformed_links"] += 1
            continue
        src, dst = first.get(link["source"]), first.get(link["target"])
        if dst is None:
            continue
        name = f"n{src}" if src is not None else ident(link["source"])
        if name not in after[dst]:
            after[dst].append(name)
        if src is not None:
            has_out.add(src)
    caps, stages = {}, []
    for i, n in enumerate(nodes):
        tool = n["task"]
        caps.setdefault(tool, Capability(ident(tool), "custom", config=tool))
        args, inputs = [("tool", tool)], []
        for k, a in enumerate(n.get("arguments", [])):
            key, value = (a.get("name", f"a{k}"), a.get("value")) if isinstance(a, dict) else (f"a{k}", a)
            m = REF.match(str(value))
            if m:
                inputs.append(f"n{int(m.group(1)) - offset}")
            else:
                args.append((ident(str(key)) or f"a{k}", str(value)))
        stages.append(Stage(f"n{i}", "tool", "custom.call", after=tuple(after[i]), inputs=tuple(inputs),
                            uses=(caps[tool].name,), args=tuple(dict(args).items())))
    sinks = [f"n{i}" for i in range(len(nodes)) if i not in has_out]
    stages.append(Stage("result", "output", after=tuple(sinks)))
    return Program(tuple(caps.values()), tuple(stages)), notes
