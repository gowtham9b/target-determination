"""Per-step authority for the checked Python baselines (shared, not counted in token totals).

A Step declares what one step may reach; its methods check every operation
against that declaration before performing it. This is the Python counterpart
of TDG's capability tokens, so the checked scripts express the same
constraints as the TDG programs.
"""

import fnmatch
import os
import subprocess
from pathlib import Path

import requests

from llm import complete


class Denied(Exception):
    pass


class Step:
    def __init__(self, name, net=(), read=None, write=None, shell=(), model=None, tokens=0):
        self.name, self.net, self.shell = name, tuple(net), tuple(shell)
        self.read, self.write = read, write
        self.model, self.tokens = model, tokens

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _inside(self, path, root):
        if root is None:
            return False
        real, base = os.path.realpath(path), os.path.realpath(root)
        return os.path.commonpath([real, base]) == base

    def get(self, url):
        if not any(fnmatch.fnmatchcase(url, p) for p in self.net):
            raise Denied(f"{self.name}: {url}")
        return requests.get(url, allow_redirects=False)

    def read_text(self, path):
        if not self._inside(path, self.read):
            raise Denied(f"{self.name}: read {path}")
        return Path(path).read_text()

    def write_text(self, path, text):
        if not self._inside(path, self.write):
            raise Denied(f"{self.name}: write {path}")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        return Path(path).write_text(text)

    def run(self, argv):
        if " ".join(argv) not in self.shell:
            raise Denied(f"{self.name}: {argv}")
        return subprocess.run(argv, capture_output=True, text=True, check=True).stdout

    def complete(self, model, prompt):
        if model != self.model or len(prompt.split()) > self.tokens:
            raise Denied(f"{self.name}: model {model}")
        self.tokens -= len(prompt.split())
        return complete(model=model, prompt=prompt, max_tokens=self.tokens)
