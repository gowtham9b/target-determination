"""Capability tokens and the enforcer that checks every external operation.

Tools never touch the file system, network, shell or model directly; they go
through a Gate bound to one stage, and every Gate call is checked by the
Enforcer against a token issued to that stage.
"""

from __future__ import annotations

import fcntl
import fnmatch
import itertools
import os
import shlex
import shutil
import stat
import threading
import time
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from .core import Capability, TdgError


class CapabilityDenied(TdgError):
    def __init__(self, stage: str, kind: str, target: str, reason: str):
        self.stage, self.kind, self.target, self.reason = stage, kind, target, reason
        super().__init__(f"{stage}: {kind} access to {target!r} denied ({reason})")


@dataclass(frozen=True)
class Token:
    id: int
    stage: str
    cap: Capability


_MODE_RANK = {"read": {"read"}, "write": {"write"}, "rw": {"read", "write"}}


def _within(path: str, root: str) -> bool:
    return os.path.commonpath([path, root]) == root


def fd_path(fd: int) -> str:
    """The location of the object an open descriptor refers to."""
    if hasattr(fcntl, "F_GETPATH"):
        return os.fsdecode(fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(1024)).rstrip(b"\0"))
    return os.readlink(f"/proc/self/fd/{fd}")


SANDBOX_EXEC = shutil.which("sandbox-exec")

_URL_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%")
_HOST_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-.")


def _noncanonical(url: str) -> str | None:
    """Why `url` might be read differently by different parsers, or None."""
    if any(ch not in _URL_CHARS for ch in url):
        return "character outside RFC 3986"
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not url.startswith(parts.scheme + "://"):
        return "scheme"
    authority = url[len(parts.scheme) + 3:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in authority or "%" in authority or "[" in authority:
        return "user information, encoded or literal-address host"
    host, _, port = authority.partition(":")
    if not host or any(ch not in _HOST_CHARS for ch in host) or host.startswith(".") or host.endswith(".") \
            or ".." in host or host.replace(".", "").isdigit():
        return "host not a plain lowercase name"
    if port and (not port.isdigit() or str(int(port)) != port or not 0 < int(port) < 65536):
        return "port"
    segments = parts.path.replace("%2e", ".").replace("%2E", ".").split("/")
    if any(s in (".", "..") for s in segments) or "%2f" in parts.path.lower() or "%5c" in parts.path.lower():
        return "dot segment or encoded separator in path"
    return None


def _sbpl(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Enforcer:
    def __init__(self, workdir: str, shell_matching: str = "argv", fs_check: str = "descriptor",
                 shell_sandbox: bool = True, url_check: str = "strict"):
        """shell_matching: "argv" matches each argument against the pattern's
        tokens and rejects absolute or parent-relative paths; "line" globs the
        whole command line (kept as the naive variant for evaluation).

        fs_check: "descriptor" verifies the object actually opened (its real
        location and link count), which closes check-to-use races; "path"
        checks the resolved path and then opens it (the earlier design).

        shell_sandbox: run permitted commands under an OS sandbox that denies
        network access, all file writes, and reads inside the working
        directory outside the pattern's directories.

        url_check: "strict" denies any URL that is not in a canonical form on
        which URL parsers agree (no backslash, whitespace, control or non-ASCII
        characters, no user information, a plain lowercase ASCII host);
        "lenient" checks whatever urllib.parse makes of the string."""
        self.workdir = os.path.realpath(workdir)
        self.shell_matching = shell_matching
        self.fs_check = fs_check
        self.shell_sandbox = shell_sandbox
        self.url_check = url_check
        self._tokens: dict[int, Token] = {}
        self._ids = itertools.count(1)
        self._spent: dict[tuple[int, str], int] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------ issuing
    def issue(self, stage: str, cap: Capability) -> Token:
        with self._lock:
            tok = Token(next(self._ids), stage, cap)
            self._tokens[tok.id] = tok
            return tok

    def attenuate(self, tok: Token, **narrower) -> Token:
        """Issue a token with a scope no wider than `tok`'s."""
        self._registered(tok, tok.stage)
        c = tok.cap
        new = replace(c, **narrower)
        if c.kind == "fs":
            if not _within(self._root(new), self._root(c)):
                raise CapabilityDenied(tok.stage, "fs", new.root, "attenuation cannot widen root")
            if not _MODE_RANK[new.mode] <= _MODE_RANK[c.mode]:
                raise CapabilityDenied(tok.stage, "fs", new.mode, "attenuation cannot add modes")
        elif c.kind in ("net", "shell"):
            if not set(new.allow) <= set(c.allow):
                raise CapabilityDenied(tok.stage, c.kind, ",".join(new.allow), "attenuation cannot add patterns")
        elif c.kind == "model":
            if new.model_id != c.model_id or new.max_tokens > c.max_tokens:
                raise CapabilityDenied(tok.stage, "model", str(new.max_tokens), "attenuation cannot raise ceiling")
        elif new != c:
            raise CapabilityDenied(tok.stage, c.kind, c.name, "custom capabilities cannot be attenuated")
        return self.issue(tok.stage, new)

    # ------------------------------------------------------------ checks
    def _registered(self, tok: Token, stage: str) -> None:
        known = self._tokens.get(tok.id)
        if known is None or known != tok:
            raise CapabilityDenied(stage, tok.cap.kind, tok.cap.name, "token was not issued by this runtime")
        if known.stage != stage:
            raise CapabilityDenied(stage, tok.cap.kind, tok.cap.name, f"token belongs to stage {known.stage!r}")

    def _root(self, cap: Capability) -> str:
        return os.path.realpath(os.path.join(self.workdir, cap.root))

    def check_fs(self, stage: str, tok: Token, path: str, mode: str) -> str:
        self._registered(tok, stage)
        if tok.cap.kind != "fs":
            raise CapabilityDenied(stage, "fs", path, "token is not a file-system capability")
        real = os.path.realpath(os.path.join(self.workdir, path))
        if not _within(real, self._root(tok.cap)):
            raise CapabilityDenied(stage, "fs", path, "path outside declared root")
        if mode not in _MODE_RANK[tok.cap.mode]:
            raise CapabilityDenied(stage, "fs", path, f"{mode} not permitted by mode {tok.cap.mode}")
        return real

    def _verify_fd(self, stage: str, tok: Token, path: str, fd: int, directory: bool = False) -> None:
        """Deny unless the opened object lies inside the root and has no other names."""
        root = self._root(tok.cap)
        where = fd_path(fd)
        st = os.fstat(fd)
        if not _within(os.path.realpath(where), root):
            os.close(fd)
            raise CapabilityDenied(stage, "fs", path, "opened object lies outside declared root")
        if not directory and stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
            os.close(fd)
            raise CapabilityDenied(stage, "fs", path, "file has other hard links")

    def open_fs(self, stage: str, tok: Token, path: str, mode: str) -> int:
        """Check, open and (in descriptor mode) re-check; returns a descriptor."""
        real = self.check_fs(stage, tok, path, mode)
        if self.fs_check == "path":
            if mode == "write":
                os.makedirs(os.path.dirname(real), exist_ok=True)
                return os.open(real, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            return os.open(real, os.O_RDONLY)
        if mode == "read":
            fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW)
            self._verify_fd(stage, tok, path, fd)
            return fd
        parent, name = os.path.split(real)
        os.makedirs(parent, exist_ok=True)
        dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        self._verify_fd(stage, tok, path, dfd, directory=True)
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o644, dir_fd=dfd)
        finally:
            os.close(dfd)
        self._verify_fd(stage, tok, path, fd)
        os.ftruncate(fd, 0)
        return fd

    def check_net(self, stage: str, tok: Token, url: str) -> None:
        self._registered(tok, stage)
        if tok.cap.kind != "net":
            raise CapabilityDenied(stage, "net", url, "token is not a network capability")
        if self.url_check == "strict":
            reason = _noncanonical(url)
            if reason:
                raise CapabilityDenied(stage, "net", url, f"ambiguous URL ({reason})")
        parts = urlsplit(url)
        if not parts.scheme or not parts.hostname:
            raise CapabilityDenied(stage, "net", url, "malformed URL")
        for pattern in tok.cap.allow:
            p = urlsplit(pattern)
            if (p.scheme == parts.scheme and p.hostname == parts.hostname
                    and p.port == parts.port and fnmatch.fnmatchcase(parts.path or "/", p.path or "/")):
                return
        raise CapabilityDenied(stage, "net", url, "endpoint not in allow list")

    def check_shell(self, stage: str, tok: Token, argv: list[str]) -> None:
        self._registered(tok, stage)
        if tok.cap.kind != "shell":
            raise CapabilityDenied(stage, "shell", " ".join(argv), "token is not a shell capability")
        line = shlex.join(argv)
        if self.shell_matching == "line":
            if any(fnmatch.fnmatchcase(line, p) for p in tok.cap.allow):
                return
            raise CapabilityDenied(stage, "shell", line, "command not in allow list")
        for arg in argv[1:]:
            if os.path.isabs(arg) or ".." in arg.replace("\\", "/").split("/"):
                raise CapabilityDenied(stage, "shell", line, "argument escapes the working directory")
        for pattern in tok.cap.allow:
            want = shlex.split(pattern)
            if len(want) == len(argv) and all(fnmatch.fnmatchcase(a, w) for a, w in zip(argv, want)):
                for a, w in zip(argv[1:], want[1:]):
                    if "/" in w and not self._arg_within(a, w):
                        raise CapabilityDenied(stage, "shell", line, "path argument resolves outside its pattern")
                return
        raise CapabilityDenied(stage, "shell", line, "command not in allow list")

    def _pattern_dir(self, pattern: str) -> str:
        literal = pattern
        for ch in "*?[":
            literal = literal.split(ch, 1)[0]
        return os.path.realpath(os.path.join(self.workdir, os.path.dirname(literal)))

    def _arg_within(self, arg: str, pattern: str) -> bool:
        return _within(os.path.realpath(os.path.join(self.workdir, arg)), self._pattern_dir(pattern))

    def sandbox_argv(self, tok: Token, argv: list[str]) -> list[str]:
        """Wrap a permitted command in an OS sandbox derived from the capability."""
        if not self.shell_sandbox:
            return argv
        if SANDBOX_EXEC is None:
            raise CapabilityDenied(tok.stage, "shell", " ".join(argv), "no OS sandbox available on this platform")
        dirs = sorted({self._pattern_dir(w) for p in tok.cap.allow for w in shlex.split(p)[1:] if "/" in w})
        rules = ["(version 1)", "(allow default)", "(deny network*)", "(deny file-write*)",
                 '(allow file-write* (literal "/dev/null"))', f"(deny file-read* (subpath {_sbpl(self.workdir)}))",
                 f"(allow file-read-metadata (subpath {_sbpl(self.workdir)}))"]
        rules += [f"(allow file-read* (subpath {_sbpl(d)}))" for d in dirs]
        return [SANDBOX_EXEC, "-p", "".join(rules), *argv]

    def check_model(self, stage: str, tok: Token, model_id: str, tokens: int) -> None:
        self._registered(tok, stage)
        if tok.cap.kind != "model":
            raise CapabilityDenied(stage, "model", model_id, "token is not a model capability")
        if model_id != tok.cap.model_id:
            raise CapabilityDenied(stage, "model", model_id, "model id not permitted")
        with self._lock:
            spent = self._spent.get((tok.id, stage), 0)
            if spent + tokens > tok.cap.max_tokens:
                raise CapabilityDenied(stage, "model", model_id, f"token ceiling {tok.cap.max_tokens} exceeded")
            self._spent[(tok.id, stage)] = spent + tokens

    def check_custom(self, stage: str, tok: Token, request: str, validator) -> None:
        self._registered(tok, stage)
        if tok.cap.kind != "custom" or not validator(tok.cap.config, request):
            raise CapabilityDenied(stage, "custom", request, "custom validator refused")


class Gate:
    """The only route from a tool to the outside world for one stage."""

    def __init__(self, enforcer: Enforcer, stage: str, tokens: list[Token], world):
        self.enforcer, self.stage, self.tokens, self.world = enforcer, stage, tokens, world
        self.check_ns = 0

    def _pick(self, kind: str, check) -> Token:
        t0 = time.perf_counter_ns()
        try:
            last = None
            for tok in self.tokens:
                if tok.cap.kind != kind:
                    continue
                try:
                    check(tok)
                    return tok
                except CapabilityDenied as e:
                    last = e
            if last is not None:
                raise last
            raise CapabilityDenied(self.stage, kind, "-", f"stage holds no {kind} capability")
        finally:
            self.check_ns += time.perf_counter_ns() - t0

    def read_file(self, path: str) -> str:
        holder = {}
        self._pick("fs", lambda t: holder.setdefault("fd", self.enforcer.open_fs(self.stage, t, path, "read")))
        self.world.storage_delay()
        with os.fdopen(holder["fd"], encoding="utf-8") as f:
            return f.read()

    def write_file(self, path: str, content: str) -> int:
        holder = {}
        self.world.storage_delay()
        self._pick("fs", lambda t: holder.setdefault("fd", self.enforcer.open_fs(self.stage, t, path, "write")))
        with os.fdopen(holder["fd"], "w", encoding="utf-8") as f:
            return f.write(content)

    def http_get(self, url: str) -> dict:
        self._pick("net", lambda t: self.enforcer.check_net(self.stage, t, url))
        return self.world.http_get(url)

    def run(self, argv: list[str]) -> str:
        holder = {}
        self._pick("shell", lambda t: holder.setdefault(
            "argv", (self.enforcer.check_shell(self.stage, t, argv), self.enforcer.sandbox_argv(t, argv))[1]))
        return self.world.run(holder["argv"], cwd=self.enforcer.workdir)

    def model(self, model_id: str, prompt: str, stochastic: bool) -> tuple[str, int]:
        cost = self.world.model_cost(prompt)
        self._pick("model", lambda t: self.enforcer.check_model(self.stage, t, model_id, cost))
        return self.world.model(model_id, prompt, stochastic), cost

    def custom(self, tool: str, request: str) -> str:
        self._pick("custom", lambda t: self.enforcer.check_custom(
            self.stage, t, tool, lambda config, req: config == req))
        return self.world.custom(tool, request)
