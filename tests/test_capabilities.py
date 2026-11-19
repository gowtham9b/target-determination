import os

import pytest

from tdg.capabilities import CapabilityDenied, Enforcer, Gate
from tdg.core import Capability
from tdg.ops import World

FS_R = Capability("d", "fs", root="data", mode="read")
FS_W = Capability("o", "fs", root="out", mode="write")
NET = Capability("n", "net", allow=("https://api.example.com/v1/*",))
SH = Capability("s", "shell", allow=("wc -l data/*.csv",))
MODEL = Capability("m", "model", model_id="mock-1", max_tokens=10)


def gate(workdir, stage, *caps, world=None):
    e = Enforcer(workdir)
    return e, Gate(e, stage, [e.issue(stage, c) for c in caps], world or World())


def test_read_inside_root(workdir):
    _, g = gate(workdir, "s", FS_R)
    assert g.read_file("data/events.csv").startswith("ts,event")


@pytest.mark.parametrize("path", ["private/secret.txt", "data/../private/secret.txt", "/etc/hosts"])
def test_read_outside_root_denied(workdir, path):
    _, g = gate(workdir, "s", FS_R)
    with pytest.raises(CapabilityDenied, match="outside declared root"):
        g.read_file(path)


def test_symlink_escape_denied(workdir):
    os.symlink(os.path.join(workdir, "private", "secret.txt"), os.path.join(workdir, "data", "link.txt"))
    _, g = gate(workdir, "s", FS_R)
    with pytest.raises(CapabilityDenied):
        g.read_file("data/link.txt")


def test_write_with_read_token_denied(workdir):
    _, g = gate(workdir, "s", FS_R)
    with pytest.raises(CapabilityDenied, match="write not permitted"):
        g.write_file("data/new.txt", "x")


def test_write_inside_write_root(workdir):
    _, g = gate(workdir, "s", FS_W)
    assert g.write_file("out/a.txt", "abc") == 3


@pytest.mark.parametrize("url", [
    "https://evil.example.com/v1/x", "http://api.example.com/v1/x",
    "https://api.example.com/v2/x", "https://api.example.com:8443/v1/x", "not a url",
])
def test_network_outside_allow_list_denied(workdir, url):
    _, g = gate(workdir, "s", NET)
    with pytest.raises(CapabilityDenied):
        g.http_get(url)


def test_network_inside_allow_list(workdir):
    _, g = gate(workdir, "s", NET, world=World({"https://api.example.com/v1/x": {"status": 200, "body": "ok"}}))
    assert g.http_get("https://api.example.com/v1/x") == {"status": 200, "body": "ok"}


def test_shell_allow_list(workdir):
    _, g = gate(workdir, "s", SH)
    assert "101" in g.run(["wc", "-l", "data/events.csv"])
    for argv in (["cat", "data/events.csv"], ["wc", "-l", "private/secret.txt"], ["wc", "-l", "data/x.csv;", "rm"]):
        with pytest.raises(CapabilityDenied):
            g.run(argv)


@pytest.mark.parametrize("argv", [
    ["wc", "-l", "data/../private/secret.txt"],
    ["wc", "-l", "data/events.csv", "private/secret.csv"],
    ["wc", "-l", "data/link.csv"],
])
def test_shell_argument_smuggling_denied(workdir, argv):
    os.symlink(os.path.join(workdir, "private", "secret.txt"), os.path.join(workdir, "data", "link.csv"))
    _, g = gate(workdir, "s", SH)
    with pytest.raises(CapabilityDenied):
        g.run(argv)


def test_naive_line_matching_admits_smuggling(workdir):
    e = Enforcer(workdir, shell_matching="line")
    tok = e.issue("s", SH)
    e.check_shell("s", tok, ["wc", "-l", "data/events.csv", "private/secret.csv"])


def test_os_sandbox_blocks_what_naive_matching_admits(workdir):
    with open(os.path.join(workdir, "private", "k.csv"), "w") as f:
        f.write("secret\n")
    e = Enforcer(workdir, shell_matching="line")
    g = Gate(e, "s", [e.issue("s", SH)], World())
    argv = ["wc", "-l", "data/../private/k.csv"]
    e.check_shell("s", e.issue("s", SH), argv)  # the naive matcher admits it
    with pytest.raises(Exception, match="not permitted"):
        g.run(argv)


def test_hard_link_alias_denied(workdir):
    os.link(os.path.join(workdir, "private", "secret.txt"), os.path.join(workdir, "data", "alias.txt"))
    _, g = gate(workdir, "s", FS_R)
    with pytest.raises(CapabilityDenied, match="hard links"):
        g.read_file("data/alias.txt")


def test_descriptor_check_catches_swapped_directory(workdir):
    os.makedirs(os.path.join(workdir, "data", "sub"))
    e = Enforcer(workdir)
    tok = e.issue("s", FS_R)
    real = e.check_fs("s", tok, "data/sub/secret.txt", "read")
    os.rmdir(os.path.join(workdir, "data", "sub"))
    os.symlink(os.path.join(workdir, "private"), os.path.join(workdir, "data", "sub"))
    e.check_fs = lambda *a: real  # the path check already passed before the swap
    with pytest.raises(CapabilityDenied, match="outside declared root"):
        e.open_fs("s", tok, "data/sub/secret.txt", "read")


def test_model_ceiling_is_cumulative(workdir):
    _, g = gate(workdir, "s", MODEL)
    g.model("mock-1", "one two three four five six", False)
    with pytest.raises(CapabilityDenied, match="ceiling"):
        g.model("mock-1", "seven eight nine ten eleven", False)


def test_model_id_checked(workdir):
    _, g = gate(workdir, "s", MODEL)
    with pytest.raises(CapabilityDenied, match="model id"):
        g.model("other", "hi", False)


def test_token_not_transferable_to_sibling(workdir):
    e = Enforcer(workdir)
    tok = e.issue("a", FS_R)
    with pytest.raises(CapabilityDenied, match="belongs to stage 'a'"):
        e.check_fs("b", tok, "data/events.csv", "read")


def test_forged_token_rejected(workdir):
    from tdg.capabilities import Token
    e = Enforcer(workdir)
    with pytest.raises(CapabilityDenied, match="not issued"):
        e.check_fs("a", Token(999, "a", FS_R), "data/events.csv", "read")


def test_attenuation_narrows(workdir):
    e = Enforcer(workdir)
    tok = e.issue("a", Capability("d", "fs", root=".", mode="rw"))
    narrow = e.attenuate(tok, root="data", mode="read")
    e.check_fs("a", narrow, "data/events.csv", "read")
    with pytest.raises(CapabilityDenied):
        e.check_fs("a", narrow, "out/x", "write")


@pytest.mark.parametrize("change", [{"root": "."}, {"mode": "rw"}])
def test_attenuation_cannot_widen(workdir, change):
    e = Enforcer(workdir)
    tok = e.issue("a", FS_R)
    with pytest.raises(CapabilityDenied, match="attenuation"):
        e.attenuate(tok, **change)


def test_stage_without_capability_denied(workdir):
    _, g = gate(workdir, "s")
    with pytest.raises(CapabilityDenied, match="holds no fs"):
        g.read_file("data/events.csv")
