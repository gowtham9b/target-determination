import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "bench")]

import workloads  # noqa: E402


@pytest.fixture
def workdir(tmp_path):
    return workloads.prepare_workdir(str(tmp_path))
