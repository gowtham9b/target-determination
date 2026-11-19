# Target Determination in Capability-Safe, Self-Repairing Directed Acyclic Pipelines

Prototype and evaluation artifact for TDG, a declarative notation in which an agent's pipeline is a typed DAG with per-stage capabilities, constraint predicates and violation policies.

## Layout

- `tdg/`: parser, compiler, runtime, capability enforcer, repair engine and command-line interface.
- `tests/`: unit tests (`pytest`).
- `bench/run_bench.py`: workloads W1 to W5 (tokens, parse and compile cost, scheduling, capability trials, repair trials, replay).
- `bench/run_icoabcd.py`: TaskBench graphs, conflict serialization, URL, path and shell fuzzing, check-to-use races, real HTTP, the authority gate, generic mutations, overhead and baselines.
- `bench/gen_study.py`, `bench/gen_tasks.py`, `bench/gen_harness.py`: the model-generation study.
- `bench/baselines/`: Python script, Python script with per-step checks, and Airflow versions of the workloads.
- `bench/results/`: raw results, including every model response in `results/gen/`.
- `bench/make_figures.py`: draws the result graphs from `bench/results/`.

## Running

Requires Python 3.12 and macOS for the shell sandbox (`sandbox-exec`).

```sh
pip install -r requirements.txt
python -m pytest
python bench/run_bench.py
sh bench/fetch_taskbench.sh        # TaskBench data at the pinned commit
python bench/run_icoabcd.py
python bench/make_figures.py
```

The generation study calls a model through the Cursor command-line agent: run `python bench/gen_study.py generate` with `CURSOR_API_KEY` set, then `python bench/gen_study.py evaluate` in an isolated environment, because it runs model-written code. Cached responses in `bench/results/gen/` let `evaluate` run without new model calls.

Some experiments need the operating-system sandbox or the network and must run outside any enclosing sandbox.
