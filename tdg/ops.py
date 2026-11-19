"""Tool, transform and branch implementations, and the simulated outside world.

Network and model calls are served by an in-process World so that runs are
reproducible and never leave the machine; file-system and shell calls are
real. Every external effect goes through a capabilities.Gate.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import random
import socket
import ssl
import subprocess
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from .core import TdgError


class World:
    """Deterministic stand-ins for remote endpoints and a language model."""

    def __init__(self, endpoints: dict[str, Any] | None = None, latency_s: float = 0.0,
                 shell_timeout_s: float = 10.0, storage_jitter_s: float = 0.0):
        # url -> response dict, or list of response dicts served in order (last one repeats)
        self.endpoints = dict(endpoints or {})
        self.latency_s = latency_s
        self.shell_timeout_s = shell_timeout_s
        self.storage_jitter_s = storage_jitter_s
        self._calls: dict[str, int] = {}
        self._lock = threading.Lock()

    def storage_delay(self) -> None:
        """Random delay before a file operation, used to expose scheduling races."""
        if self.storage_jitter_s:
            time.sleep(random.random() * self.storage_jitter_s)

    def custom(self, tool: str, request: str) -> str:
        if self.latency_s:
            time.sleep(self.latency_s)
        return f"{tool}[{hashlib.sha256(f'{tool}:{request}'.encode()).hexdigest()[:12]}]"

    def http_get(self, url: str) -> dict:
        if self.latency_s:
            time.sleep(self.latency_s)
        spec = self.endpoints.get(url, {"status": 404, "body": ""})
        if isinstance(spec, list):
            with self._lock:
                i = self._calls.get(url, 0)
                self._calls[url] = i + 1
            spec = spec[min(i, len(spec) - 1)]
        return {"status": spec["status"], "body": spec["body"]}

    def run(self, argv: list[str], cwd: str) -> str:
        done = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                              timeout=self.shell_timeout_s, check=False)
        if done.returncode != 0:
            raise TdgError(f"command exited with {done.returncode}: {done.stderr.strip()[:200]}")
        return done.stdout

    @staticmethod
    def model_cost(prompt: str) -> int:
        return max(1, len(prompt.split()))

    def model(self, model_id: str, prompt: str, stochastic: bool) -> str:
        if self.latency_s:
            time.sleep(self.latency_s)
        h = hashlib.sha256(f"{model_id}:{' '.join(prompt.split())}".encode()).hexdigest()[:12]
        text = f"summary[{h}] of {len(prompt.split())} words"
        if stochastic:
            text += f" #{random.SystemRandom().randint(0, 10**6)}"
        return text


class HttpWorld(World):
    """Real HTTP(S) over sockets for net.get; other operations as in World.

    The host is resolved once and the connection is made to that address, so
    a second resolution cannot redirect it; link-local, multicast and
    unspecified addresses are refused; redirects are returned, never
    followed; time and response size are bounded.
    """

    def __init__(self, timeout_s: float = 5.0, max_bytes: int = 1 << 20, resolver=None, **kw):
        super().__init__(**kw)
        self.timeout_s, self.max_bytes = timeout_s, max_bytes
        self.resolver = resolver or (lambda host, port: [
            a[4][0] for a in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)])

    def _connect(self, host: str, port: int) -> socket.socket:
        ips = self.resolver(host, port)
        ips = [ips] if isinstance(ips, str) else list(ips)
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            if addr.is_link_local or addr.is_multicast or addr.is_unspecified:
                raise TdgError(f"{host} resolved to forbidden address {ip}")
        last = None
        for ip in ips:
            try:
                return socket.create_connection((ip, port), timeout=self.timeout_s)
            except OSError as e:
                last = e
        raise last or TdgError(f"{host} did not resolve")

    def http_get(self, url: str) -> dict:
        parts = urlsplit(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        sock = self._connect(parts.hostname, port)
        if parts.scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=parts.hostname)
            conn = http.client.HTTPSConnection(parts.hostname, port, timeout=self.timeout_s, context=ctx)
        else:
            conn = http.client.HTTPConnection(parts.hostname, port, timeout=self.timeout_s)
        conn.sock = sock
        try:
            target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            conn.request("GET", target, headers={"Host": parts.netloc, "User-Agent": "tdg/0.3",
                                                 "Accept-Encoding": "identity"})
            resp = conn.getresponse()
            body = resp.read(self.max_bytes + 1)
            if len(body) > self.max_bytes:
                raise TdgError(f"response larger than {self.max_bytes} bytes")
            return {"status": resp.status, "body": body.decode("utf-8", errors="replace")}
        finally:
            conn.close()


def _one(inputs: list[Any]) -> Any:
    if len(inputs) != 1:
        raise TdgError(f"expected exactly one input, got {len(inputs)}")
    return inputs[0]


def _as_text(v: Any) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, dict) and set(v) == {"status", "body"}:
        return v["body"]
    return json.dumps(v, sort_keys=True)


def _field(inputs, args):
    v = _one(inputs)
    if isinstance(v, dict) and set(v) == {"status", "body"}:
        v = v["body"]
    if isinstance(v, str):
        v = json.loads(v)
    for key in str(args["key"]).split("."):
        if isinstance(v, dict):
            v = v.get(key)
        elif isinstance(v, list) and key.isdigit() and int(key) < len(v):
            v = v[int(key)]
        else:
            v = None
        if v is None:
            return None
    return v


TRANSFORM_IMPLS = {
    "identity": lambda inputs, args: _one(inputs),
    "body": lambda inputs, args: _one(inputs)["body"],
    "status": lambda inputs, args: _one(inputs)["status"],
    "parse_json": lambda inputs, args: json.loads(_as_text(_one(inputs))),
    "field": _field,
    "count": lambda inputs, args: len(_one(inputs) or []),
    "length": lambda inputs, args: len(_as_text(_one(inputs))),
    "sum": lambda inputs, args: sum(_one(inputs)),
    "upper": lambda inputs, args: _as_text(_one(inputs)).upper(),
    "concat": lambda inputs, args: str(args.get("sep", "")).join(_as_text(v) for v in inputs),
    "template": lambda inputs, args: str(args["text"]).format(*inputs),
    "merge": lambda inputs, args: {str(i): v for i, v in enumerate(inputs)},
}

BRANCH_IMPLS = {
    "gt": lambda inputs, args: _one(inputs) > args["value"],
    "lt": lambda inputs, args: _one(inputs) < args["value"],
    "eq": lambda inputs, args: _one(inputs) == args["value"],
    "truthy": lambda inputs, args: bool(_one(inputs)),
}


def run_tool(op: str, args: dict, inputs: list[Any], gate, stochastic: bool) -> tuple[Any, int]:
    """Execute a tool through `gate`. Returns (output, model tokens used)."""
    if op == "net.get":
        return gate.http_get(args["url"]), 0
    if op == "fs.read":
        return gate.read_file(args["path"]), 0
    if op == "fs.write":
        content = args.get("text") if "text" in args else "\n".join(_as_text(v) for v in inputs)
        return gate.write_file(args["path"], content), 0
    if op == "shell.run":
        argv = [str(args["cmd"])] + [str(a) for a in str(args.get("args", "")).split()]
        return gate.run(argv), 0
    if op == "model.call":
        prompt = str(args.get("prompt", "")) + " " + " ".join(_as_text(v) for v in inputs)
        return gate.model(str(args["model"]), prompt.strip(), stochastic)
    if op == "custom.call":
        request = json.dumps({"args": args, "inputs": [_as_text(v) for v in inputs]}, sort_keys=True)
        return gate.custom(str(args["tool"]), request), 0
    raise TdgError(f"tool {op} is not implemented")
