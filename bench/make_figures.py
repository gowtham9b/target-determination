"""Result graphs for paper-icoabcd, drawn from results/*.json. Writes ../figures/*.pdf."""

import json
from pathlib import Path

import matplotlib

matplotlib.use("pdf")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).resolve().parent
FIG = HERE.parent / "figures"
R = json.loads((HERE / "results" / "icoabcd.json").read_text())
B = json.loads((HERE / "results" / "bench.json").read_text())
P = json.loads((HERE / "results" / "bench_v2_prior.json").read_text())  # earlier prototype

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "Times"], "font.size": 8,
    "axes.titlesize": 8, "axes.labelsize": 8, "xtick.labelsize": 7.5, "ytick.labelsize": 7.5,
    "legend.fontsize": 7, "pdf.fonttype": 42, "axes.linewidth": 0.6, "axes.spines.top": False,
    "axes.spines.right": False, "xtick.major.width": 0.6, "ytick.major.width": 0.6,
})
W = 3.45  # IEEE column width in inches
DARK, LIGHT, MID = "#2b2b2b", "#b8b8b8", "#7a7a7a"


def security():
    u, p, s, t = R["url_fuzz"]["modes"], R["path_fuzz"]["modes"], R["shell_fuzz"], R["toctou"]
    c = R["conflicts"]
    rows = [
        ("URL bypasses", u["lenient"]["bypass_any"], u["strict"]["bypass_any"]),
        ("Private-file reads", p["path"]["private_file_reads"], p["descriptor"]["private_file_reads"]),
        ("Shell escapes admitted", s["matchers"]["line"]["admitted_escapes"], s["matchers"]["argv"]["admitted_escapes"]),
        ("Race escapes", t["path"]["secret"] + t["path"]["writes_landing_outside_root"],
         t["descriptor"]["secret"] + t["descriptor"]["writes_landing_outside_root"]),
        ("Divergent schedules", c["unserialized"]["programs_with_divergent_outcomes"],
         c["serialized"]["programs_with_divergent_outcomes"]),
        ("Ranked widening repairs", P["repair"]["summary"]["url_host_typo"]["top1_authority"],
         B["repair"]["summary"]["url_host_typo"]["top1_authority"]),
    ]
    fig, ax = plt.subplots(figsize=(2.55, 1.42))
    y = range(len(rows))[::-1]
    ax.barh([v + 0.19 for v in y], [r[1] for r in rows], height=0.36, color=LIGHT, label="Earlier design")
    ax.barh([v - 0.19 for v in y], [r[2] for r in rows], height=0.36, color=DARK, label="Revised design")
    for v, r in zip(y, rows):
        ax.text(r[1] + 2, v + 0.19, str(r[1]), va="center", fontsize=7)
        ax.text(r[2] + 2, v - 0.19, str(r[2]), va="center", fontsize=7)
    ax.set_yticks(list(y))
    ax.set_yticklabels([r[0] for r in rows])
    ax.set_xlabel("Failures observed (count)")
    ax.set_xlim(0, 175)
    ax.legend(loc="lower center", bbox_to_anchor=(0.35, 1.0), ncol=2, frameon=False)
    fig.savefig(FIG / "fig_security.pdf", bbox_inches="tight")


def _mutation_bar(rows):
    det = [r for r in rows if r["kind"] in ("compile", "runtime", "blocked")]
    c = [r["confidence"] for r in det if "confidence" in r]
    intended = sum(x["top1_intended"] for x in c)
    resolved = sum(x["top1_resolves"] for x in c) - intended
    authority = sum(x["proposals"] == 0 and x["authority_requests"] > 0 for x in c)
    return {"Restored intended program": intended, "Resolved, intent changed": resolved,
            "Authority request only": authority,
            "Detected, no fix": len(det) - intended - resolved - authority,
            "Undetected, wrong result": sum(r["kind"] == "silently_wrong" for r in rows),
            "No observable effect": sum(r["kind"] == "equivalent" for r in rows)}


def repair():
    rep, gate = B["repair"]["summary"], R["repair_gate"]
    n = sum(v["n"] for v in rep.values())
    intended = sum(v["top1_intended"] for v in rep.values())
    resolved = sum(v["top1_resolves"] for v in rep.values()) - intended
    authority = sum(v["authority_requests"] for k, v in gate.items() if v["ordinary_top1_resolves"] == 0)
    detected = sum(v["detected"] for v in rep.values())
    designed = {"Restored intended program": intended, "Resolved, intent changed": resolved,
                "Authority request only": authority,
                "Detected, no fix": detected - intended - resolved - authority,
                "Undetected, wrong result": n - detected, "No observable effect": 0}
    rows = R["mutations"]["rows"]
    bars = [("Designed faults\n(250)", designed),
            (f"Generic mutations,\nworkloads ({sum(r['source'] == 'workload' for r in rows)})",
             _mutation_bar([r for r in rows if r["source"] == "workload"])),
            (f"Generic mutations,\nTaskBench ({sum(r['source'] == 'taskbench' for r in rows)})",
             _mutation_bar([r for r in rows if r["source"] == "taskbench"]))]
    cats = list(designed)
    colors = ["#1a1a1a", "#555555", "#8c8c8c", "#b3b3b3", "#ffffff", "#e0e0e0"]
    hatches = ["", "", "", "", "////", ""]
    fig, ax = plt.subplots(figsize=(2.45, 1.25))
    for i, (label, d) in enumerate(bars):
        total, left = sum(d.values()), 0
        for cat, col, h in zip(cats, colors, hatches):
            w = 100 * d[cat] / total
            ax.barh(len(bars) - 1 - i, w, left=left, color=col, edgecolor="#333333", linewidth=0.4, hatch=h,
                    height=0.6, label=cat if i == 0 else None)
            left += w
    ax.set_yticks(range(len(bars)))
    ax.set_yticklabels([b[0] for b in bars][::-1])
    ax.set_xlim(0, 100)
    ax.set_xlabel("Share of injected faults (percent)")
    ax.legend(ncol=2, loc="upper center", bbox_to_anchor=(0.30, -0.36), frameon=False, handlelength=1.2,
              columnspacing=0.8, borderaxespad=0)
    fig.savefig(FIG / "fig_repair.pdf", bbox_inches="tight")


def tokens():
    rows = R["baselines"]["rows"]
    forms = [("tdg", "TDG", DARK), ("script", "Python script", MID), ("script_checked", "Script with checks", LIGHT),
             ("airflow", "Airflow DAG", "#e6e6e6")]
    fig, ax = plt.subplots(figsize=(3.0, 1.2))
    x = range(len(rows))
    for k, (key, label, col) in enumerate(forms):
        ax.bar([i + (k - 1.5) * 0.2 for i in x], [r[key] for r in rows], width=0.2, color=col,
               edgecolor="#333333", linewidth=0.4, label=label)
    ax.set_xticks(list(x))
    ax.set_xticklabels([r["workload"] for r in rows])
    ax.set_xlabel("Workload")
    ax.set_ylabel("Tokens (o200k_base)")
    ax.legend(ncol=2, frameon=False, loc="lower center", bbox_to_anchor=(0.5, 1.0), columnspacing=1.0)
    ax.set_ylim(0, 390)
    fig.savefig(FIG / "fig_tokens.pdf", bbox_inches="tight")


def overhead():
    per = R["overhead"]["per_workload_median"]
    tb = R["taskbench"]["timing_us_median"]
    labels = list(per) + ["TaskBench"]
    comps = [("issue_us", "Token issue", DARK), ("gate_us", "Capability check", MID),
             ("predicate_us", "Predicates", LIGHT), ("trace_us", "Hashing and copying", "#ececec")]
    fig, ax = plt.subplots(figsize=(3.0, 1.2))
    for i, name in enumerate(labels):
        d = per[name]["tool"] if name in per else tb
        bottom = 0
        for key, lab, col in comps:
            ax.bar(i, d[key], bottom=bottom, width=0.55, color=col, edgecolor="#333333", linewidth=0.4,
                   label=lab if i == 0 else None)
            bottom += d[key]
        ax.text(i, bottom + 4, f"{bottom:.0f}", ha="center", fontsize=7)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels)
    ax.set_ylabel("Median per tool stage (\u00b5s)")
    ax.set_ylim(0, 255)
    ax.legend(ncol=2, frameon=False, loc="lower center", bbox_to_anchor=(0.5, 1.0), columnspacing=1.0)
    fig.savefig(FIG / "fig_overhead.pdf", bbox_inches="tight")


if __name__ == "__main__":
    FIG.mkdir(exist_ok=True)
    for f in (security, repair, tokens, overhead):
        f()
        print("wrote", f.__name__)
